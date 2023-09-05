
#[macro_use] extern crate rocket;

use sqlx::postgres::PgPoolOptions;

use rocket::serde::json::{Value, json};

mod endpoints;

#[get("/")]
fn hello() -> &'static str {
    "Hello, world!\n"
}

#[catch(404)]
fn not_found() -> Value {
    json!("Not found!")
}

#[rocket::main]
async fn main() {

    let pool = 
        PgPoolOptions::new()
        // .max_connections(5)
        .connect("postgresql://postgres:postgres@localhost/sgx")
        .await
        .unwrap();

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap();

    let _ = rocket::build()
        .mount("/", routes![
            hello,
            endpoints::musig::test,
            endpoints::deposit::post_server_pubkey,
            endpoints::deposit::get_server_pubkey,
            endpoints::musig::post_public_nonce,
            endpoints::musig::post_partial_signature,
        ])
        .register("/", catchers![
            not_found
        ])
        .manage(pool)
        // .attach(MercuryPgDatabase::fairing())
        .launch()
        .await;
}
