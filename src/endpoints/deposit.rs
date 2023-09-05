use rocket::State;
use secp256k1_zkp::{Secp256k1, SecretKey};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

#[post("/server_pubkey", format = "json")]
pub async fn post_server_pubkey(pool: &State<PgPool>) -> Value {

    let secp = Secp256k1::new();

    let server_secret_key = SecretKey::new(&mut rand::thread_rng());

    let server_pubkey = server_secret_key.public_key(&secp);

    let query = "INSERT INTO key_data (sealed_secret_key, public_key) VALUES ($1, $2)";

    let _ = sqlx::query(query)
        .bind(&server_secret_key.secret_bytes())
        .bind(&server_pubkey.serialize())
        .execute(pool.inner())
        .await
        .unwrap();

    json!({
        "server_pubkey": server_pubkey.to_string()
    })
}

#[get("/server_pubkey", format = "json")]
pub async fn get_server_pubkey(pool: &State<PgPool>) -> Value {

    // Query to fetch data
    let rows = sqlx::query("SELECT * FROM public.key_data")
        .fetch_all(pool.inner())
        .await
        .unwrap();

    let mut server_pubkeys = Vec::<String>::new();

    for row in rows {
        let public_key_bytes = row.get::<Option<Vec<u8>>, _>("public_key");

        if public_key_bytes.is_some() {

            let server_pubkey = secp256k1_zkp::PublicKey::from_slice(&public_key_bytes.unwrap()).unwrap();

            server_pubkeys.push(server_pubkey.to_string());

            /* return json!({
                "server_pubkey": server_pubkey.to_string()
            }) */
        }
    }

    json!({
        "server_pubkey": server_pubkeys
    })
}
