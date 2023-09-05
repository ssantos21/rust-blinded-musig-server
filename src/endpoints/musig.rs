use std::str::FromStr;
use rocket::{State, serde::json::Json, response::status, http::Status};
use secp256k1_zkp::{PublicKey, SecretKey, musig::{MusigSessionId, MusigSecNonce, MusigKeyAggCoef, MusigSession}, new_musig_nonce_pair, Secp256k1, ffi::{MUSIG_SECNONCE_LEN, MUSIG_KEYAGG_COEF_LEN, MUSIG_SESSION_LEN}, KeyPair};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct PublicNonceRequestPayload<'r> {
    server_public_key: &'r str,
}

#[get("/test", format = "json")]
pub fn test() -> Value {
    json!("Hello, world!")
}

#[post("/public_nonce", format = "json", data = "<public_nonce_request_payload>")]
pub async fn post_public_nonce(pool: &State<sqlx::PgPool>, public_nonce_request_payload: Json<PublicNonceRequestPayload<'_>>) -> status::Custom<Json<Value>>  {

    let server_pubkey = PublicKey::from_str(&public_nonce_request_payload.server_public_key).unwrap();

    let row = sqlx::query("SELECT sealed_secret_key FROM public.key_data WHERE public_key = $1")
        .bind(&server_pubkey.serialize())
        .fetch_one(pool.clone().inner())
        .await;

    let server_secret_key: SecretKey;

    match row {
        Ok(pg_row) => {
            let secret_key_bytes = pg_row.get::<Option<Vec<u8>>, _>("sealed_secret_key");

            server_secret_key = SecretKey::from_slice(&secret_key_bytes.unwrap()).unwrap();
        },
        Err(sqlx::Error::RowNotFound) => {
            let response_body = json!({
                "error": "Not Found",
                "message": "Public key not found."
            });
        
            return status::Custom(Status::NotFound, Json(response_body));
        },
        Err(_) => {
            let response_body = json!({
                "error": "Internal Server Error",
                "message": "Unexpected error."
            });
        
            return status::Custom(Status::InternalServerError, Json(response_body));
        },
    }

    let server_session_id = MusigSessionId::new(&mut rand::thread_rng());

    let secp = Secp256k1::new();

    let (server_sec_nonce, server_pub_nonce) = new_musig_nonce_pair(&secp, server_session_id, None, Some(server_secret_key), server_pubkey, None, None).unwrap();

    let query = "UPDATE key_data SET sealed_secnonce = $1, public_nonce = $2 WHERE public_key = $3";

    let x = server_sec_nonce.serialize();

    println!("x: {}", hex::encode(&x));
    
    let _ = sqlx::query(query)
        .bind(&x)
        .bind(&server_pub_nonce.serialize())
        .bind(&server_pubkey.serialize())
        .execute(pool.clone().inner())
        .await
        .unwrap();


    let response_body = json!({
        "server_pubnonce": hex::encode(server_pub_nonce.serialize()),
    });

    status::Custom(Status::Ok, Json(response_body))

    
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct PartialSignatureRequestPayload<'r> {
    server_public_key: &'r str,
    keyaggcoef: &'r str,
    negate_seckey: bool,
    session: &'r str,
}

#[post("/partial_signature", format = "json", data = "<partial_signature_request_payload>")]
pub async fn post_partial_signature(pool: &State<sqlx::PgPool>, partial_signature_request_payload: Json<PartialSignatureRequestPayload<'_>>) -> status::Custom<Json<Value>>  {
    
    let server_pubkey = PublicKey::from_str(&partial_signature_request_payload.server_public_key).unwrap();
    let keyaggcoef_bytes = hex::decode(&partial_signature_request_payload.keyaggcoef).unwrap();
    let negate_seckey = partial_signature_request_payload.negate_seckey;  

    let mut keyaggcoef_array = [0u8; MUSIG_KEYAGG_COEF_LEN];
    keyaggcoef_array.copy_from_slice(&keyaggcoef_bytes);

    let keyaggcoef = MusigKeyAggCoef::from_slice(keyaggcoef_array);

    let session_bytes = hex::decode(&partial_signature_request_payload.session).unwrap();

    let mut session_array = [0u8; MUSIG_SESSION_LEN];
    session_array.copy_from_slice(&session_bytes);

    let session = MusigSession::from_slice(session_array);

    // Get `sealed_secnonce` and `sealed_secret_key` from database
    
    let row = sqlx::query("SELECT sealed_secnonce, sealed_secret_key FROM public.key_data WHERE public_key = $1")
        .bind(&server_pubkey.serialize())
        .fetch_one(pool.clone().inner())
        .await;

    let server_secret_key: SecretKey;
    let server_secret_nonce: MusigSecNonce;

    match row {
        Ok(pg_row) => {
            let secret_key_bytes = pg_row.get::<Option<Vec<u8>>, _>("sealed_secret_key");
            let secret_nonce_bytes = pg_row.get::<Option<Vec<u8>>, _>("sealed_secnonce");

            let mut secret_nonce_array = [0u8; MUSIG_SECNONCE_LEN];
            secret_nonce_array.copy_from_slice(&secret_nonce_bytes.unwrap());

            server_secret_key = SecretKey::from_slice(&secret_key_bytes.unwrap()).unwrap();
            server_secret_nonce = MusigSecNonce::from_slice(secret_nonce_array);
        },
        Err(sqlx::Error::RowNotFound) => {
            let response_body = json!({
                "error": "Not Found",
                "message": "Public key not found."
            });
        
            return status::Custom(Status::NotFound, Json(response_body));
        },
        Err(_) => {
            let response_body = json!({
                "error": "Internal Server Error",
                "message": "Unexpected error."
            });
        
            return status::Custom(Status::InternalServerError, Json(response_body));
        },
    }

    let secp = Secp256k1::new();

    let server_keypair = KeyPair::from_secret_key(&secp, &server_secret_key);

    let server_partial_sig = session.blinded_partial_sign(&secp, server_secret_nonce, &server_keypair, &keyaggcoef, negate_seckey).unwrap();

    let response_body = json!({
        "partial_sig": hex::encode(server_partial_sig.serialize()),
    });

    status::Custom(Status::Ok, Json(response_body))
}
