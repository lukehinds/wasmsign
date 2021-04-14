use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use url::Url;
use open;

use openidconnect::core::{
    CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest::http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};

use crate::WError;

pub fn testmod() {
    println!("test mod");
}

pub fn OpenIDConnect() -> Result<CoreIdTokenClaims, WError> {
    env_logger::init();

    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable."),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET")
            .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
    );
    let issuer_url =
        IssuerUrl::new("https://oauth2.sigstore.dev/auth".to_string()).expect("Invalid issuer URL");

    // Fetch Google's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, http_client)
        .unwrap_or_else(|_err| {
            println!("Failed to discover OpenID Provider");
            unreachable!();
        });

    // Set up the config for the Google OAuth2 process.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        google_client_id,
        Some(google_client_secret),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
    );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    // println!(
    //     "Open this URL in your browser:\n{}\n",
    //     authorize_url.to_string()
    // );
    if open::that(authorize_url.to_string()).is_ok() {
        println!("Look at your browser !");
    }

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Secret code:\n{}\n", code.secret());
            println!(
                "Open ID state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .request(http_client)
                .unwrap_or_else(|_err| {
                    println!("Failed to access token endpoint");
                    unreachable!();
                });

            println!(
                "sigstore returned access token:\n{}\n",
                token_response.access_token().secret()
            );
            // println!("sigstore eturned scopes: {:?}", token_response.scopes());

            let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
            let id_token_claims: &CoreIdTokenClaims = token_response
                .extra_fields()
                .id_token()
                .expect("Server did not return an ID token")
                .claims(&id_token_verifier, &nonce)
                .unwrap_or_else(|_err| {
                    println!("Failed to verify ID token");
                    unreachable!();
                });
            println!("Sigstore returned ID token: {:?}", id_token_claims);

            // The server will terminate itself after collecting the first code.
            break
        }
            Ok(id_token_claims)
        }
    }
    Ok(())
}

