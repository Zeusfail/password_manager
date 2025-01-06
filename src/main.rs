use age::{
    secrecy::{ExposeSecret, SecretString},
    x25519::{Identity, Recipient},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

// Constantes de sécurité
const MAX_LOGIN_ATTEMPTS: u32 = 3;
const LOCKOUT_DURATION: u64 = 300; // 5 minutes en secondes
const MIN_PASSWORD_LENGTH: usize = 12;

#[derive(Serialize, Deserialize)]
struct EncryptedPassword {
    site: String,
    username: String,
    encrypted_data: Vec<u8>,
    nonce: Vec<u8>,
    hmac: Vec<u8>, // HMAC pour vérifier l'intégrité
}

struct LoginAttempts {
    count: u32,
    last_attempt: u64,
}

struct PasswordManager {
    db_conn: Connection,
    key: Zeroizing<Vec<u8>>,
    identity: Identity,
    hmac_key: Zeroizing<Vec<u8>>,
    login_attempts: LoginAttempts,
}

impl PasswordManager {
    fn new(master_password: &str, db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if master_password.len() < MIN_PASSWORD_LENGTH {
            return Err("Le mot de passe maître doit faire au moins 12 caractères".into());
        }

        let db_conn = Connection::open(db_path)?;
        
        // Tables avec ajout de HMAC et timestamps
        db_conn.execute(
            "CREATE TABLE IF NOT EXISTS master_key (
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                hmac_salt BLOB NOT NULL,
                last_access TIMESTAMP
            )",
            [],
        )?;

        db_conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                nonce BLOB NOT NULL,
                hmac BLOB NOT NULL,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                PRIMARY KEY (site, username)
            )",
            [],
        )?;

        db_conn.execute(
            "CREATE TABLE IF NOT EXISTS used_nonces (
                nonce BLOB PRIMARY KEY,
                created_at TIMESTAMP
            )",
            [],
        )?;

        // Génération des clés avec paramètres renforcés
        let salt = SaltString::generate(&mut OsRng);
        let hmac_salt = SaltString::generate(&mut OsRng);
        
        let argon2 = Argon2::default();
        
        let mut key = Zeroizing::new(vec![0u8; 32]);
        let mut hmac_key = Zeroizing::new(vec![0u8; 32]);
        
        argon2.hash_password_into(
            master_password.as_bytes(),
            salt.as_str().as_bytes(),
            key.as_mut_slice(),
        ).map_err(|e| format!("Erreur de hachage: {}", e))?;
        
        argon2.hash_password_into(
            master_password.as_bytes(),
            hmac_salt.as_str().as_bytes(),
            hmac_key.as_mut_slice(),
        ).map_err(|e| format!("Erreur de hachage: {}", e))?;

        let identity = Identity::generate();
        
        let verifier = argon2.hash_password(
            master_password.as_bytes(),
            &salt,
        ).map_err(|e| format!("Erreur de hachage: {}", e))?.to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        db_conn.execute(
            "INSERT OR REPLACE INTO master_key (salt, verifier, hmac_salt, last_access) 
             VALUES (?, ?, ?, ?)",
            params![salt.as_ref(), verifier, hmac_salt.as_ref(), now],
        )?;

        Ok(Self {
            db_conn,
            key,
            identity,
            hmac_key,
            login_attempts: LoginAttempts {
                count: 0,
                last_attempt: 0,
            },
        })
    }

    fn is_locked(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        self.login_attempts.count >= MAX_LOGIN_ATTEMPTS 
            && (now - self.login_attempts.last_attempt) < LOCKOUT_DURATION
    }

    fn verify_and_update_nonce(&self, nonce: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        // Vérifier si le nonce existe déjà
        let exists: bool = self
            .db_conn
            .query_row(
                "SELECT 1 FROM used_nonces WHERE nonce = ?",
                params![nonce],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if exists {
            return Err("Nonce déjà utilisé détecté".into());
        }

        // Enregistrer le nouveau nonce
        self.db_conn.execute(
            "INSERT INTO used_nonces (nonce, created_at) VALUES (?, ?)",
            params![nonce, now],
        )?;

        Ok(())
    }

    fn calculate_hmac(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.hmac_key.as_slice())
            .expect("HMAC initialization failed");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn add_password(
        &self,
        site: &str,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_locked() {
            return Err("Compte temporairement verrouillé".into());
        }

        // Génération et vérification du nonce
        let mut nonce = vec![0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        self.verify_and_update_nonce(&nonce)?;

        let cipher = ChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = Nonce::from_slice(&nonce);
        
        let encrypted_data = cipher
            .encrypt(nonce, password.as_bytes())
            .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

        // Calcul du HMAC
        let mut data_to_hmac = Vec::new();
        data_to_hmac.extend_from_slice(site.as_bytes());
        data_to_hmac.extend_from_slice(username.as_bytes());
        data_to_hmac.extend_from_slice(&encrypted_data);
        data_to_hmac.extend_from_slice(nonce.as_slice());
        
        let hmac = self.calculate_hmac(&data_to_hmac);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        self.db_conn.execute(
            "INSERT OR REPLACE INTO passwords 
             (site, username, encrypted_data, nonce, hmac, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                site,
                username,
                encrypted_data,
                nonce.as_slice(),
                hmac,
                now,
                now
            ],
        )?;

        Ok(())
    }

    fn get_password(
        &self,
        site: &str,
        username: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if self.is_locked() {
            return Err("Compte temporairement verrouillé".into());
        }

        let mut stmt = self.db_conn.prepare(
            "SELECT encrypted_data, nonce, hmac FROM passwords 
             WHERE site = ? AND username = ?",
        )?;

        let (encrypted_data, nonce, stored_hmac): (Vec<u8>, Vec<u8>, Vec<u8>) = stmt.query_row(
            params![site, username],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        // Vérification du HMAC
        let mut data_to_hmac = Vec::new();
        data_to_hmac.extend_from_slice(site.as_bytes());
        data_to_hmac.extend_from_slice(username.as_bytes());
        data_to_hmac.extend_from_slice(&encrypted_data);
        data_to_hmac.extend_from_slice(&nonce);
        
        let calculated_hmac = self.calculate_hmac(&data_to_hmac);
        
        if calculated_hmac != stored_hmac {
            return Err("Intégrité des données compromise".into());
        }

        let cipher = ChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = Nonce::from_slice(&nonce);
        
        let password = cipher
            .decrypt(nonce, encrypted_data.as_ref())
            .map_err(|e| format!("Erreur de déchiffrement: {}", e))?;

        Ok(String::from_utf8(password)?)
    }

    fn generate_password(&self, length: usize) -> String {
        if length < MIN_PASSWORD_LENGTH {
            return self.generate_password(MIN_PASSWORD_LENGTH);
        }

        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        let mut rng = OsRng;
        let mut password = String::with_capacity(length);
        
        // Assurer la présence d'au moins un caractère de chaque type
        password.push(CHARSET[..26].get(rng.next_u32() as usize % 26).unwrap().clone() as char);  // Majuscule
        password.push(CHARSET[26..52].get(rng.next_u32() as usize % 26).unwrap().clone() as char);  // Minuscule
        password.push(CHARSET[52..62].get(rng.next_u32() as usize % 10).unwrap().clone() as char);  // Chiffre
        password.push(CHARSET[62..].get(rng.next_u32() as usize % (CHARSET.len() - 62)).unwrap().clone() as char);  // Spécial
        
        // Compléter avec des caractères aléatoires
        for _ in 0..length-4 {
            let idx = (rng.next_u32() as usize) % CHARSET.len();
            password.push(CHARSET[idx] as char);
        }
        
        // Mélanger le mot de passe
        let mut chars: Vec<char> = password.chars().collect();
        for i in (1..chars.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            chars.swap(i, j);
        }
        
        chars.into_iter().collect()
    }

    fn verify_master_password(&mut self, password: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if self.is_locked() {
            return Err("Compte temporairement verrouillé".into());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        self.login_attempts.last_attempt = now;

        let (salt, verifier): (Vec<u8>, String) = self
            .db_conn
            .query_row(
                "SELECT salt, verifier FROM master_key",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;

        let parsed_hash = PasswordHash::new(&verifier).map_err(|e| format!("Error parsing hash: {}", e))?;
        let is_valid = Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();

        if !is_valid {
            self.login_attempts.count += 1;
            
            if self.login_attempts.count >= MAX_LOGIN_ATTEMPTS {
                return Err(format!(
                    "Trop de tentatives échouées. Compte verrouillé pour {} secondes",
                    LOCKOUT_DURATION
                ).into());
            }
        } else {
            self.login_attempts.count = 0;
            
            // Mettre à jour le dernier accès
            self.db_conn.execute(
                "UPDATE master_key SET last_access = ?",
                params![now],
            )?;
        }

        Ok(is_valid)
    }

    fn export_encrypted_backup(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut stmt = self.db_conn.prepare("SELECT * FROM passwords")?;
        let passwords: Vec<EncryptedPassword> = stmt
            .query_map([], |row| {
                Ok(EncryptedPassword {
                    site: row.get(0)?,
                    username: row.get(1)?,
                    encrypted_data: row.get(2)?,
                    nonce: row.get(3)?,
                    hmac: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;

        // Avertissement pour l'utilisateur
        println!("\n⚠️  AVERTISSEMENT DE SÉCURITÉ ⚠️");
        println!("La sauvegarde va être exportée. Veuillez noter que :");
        println!("1. La sauvegarde contient des données sensibles chiffrées");
        println!("2. La sécurité dépend de votre mot de passe maître");
        println!("3. Stockez ce fichier dans un endroit sûr");
        println!("4. Évitez les services cloud non chiffrés\n");

        let json = serde_json::to_string(&passwords)?;
        fs::write(path, json)?;

        Ok(())
    }

    fn cleanup_old_data(&self) -> Result<(), Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
            
        // Nettoyer les anciens nonces (plus vieux que 24h)
        self.db_conn.execute(
            "DELETE FROM used_nonces WHERE created_at < ?",
            params![now - 86400],
        )?;

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::{Input, Password, Confirm};
    use console::Term;

    let term = Term::stdout();
    println!("Gestionnaire de mots de passe sécurisé");
    println!("======================================\n");

    // Avertissement initial sur la sécurité
    println!("⚠️  Recommandations de sécurité importantes :");
    println!("1. Utilisez un mot de passe maître fort (min. {} caractères)", MIN_PASSWORD_LENGTH);
    println!("2. Ne partagez jamais votre mot de passe maître");
    println!("3. Effectuez des sauvegardes régulières\n");

    let master_password = Password::new()
        .with_prompt("Mot de passe maître")
        .with_confirmation("Confirmez le mot de passe maître", "Les mots de passe ne correspondent pas")
        .interact()?;

    let mut pm = PasswordManager::new(&master_password, "passwords.db")?;

    // Nettoyage périodique des anciennes données
    pm.cleanup_old_data()?;

    loop {
        term.clear_screen()?;
        println!("\nMenu Principal");
        println!("=============");
        println!("1. Ajouter un mot de passe");
        println!("2. Récupérer un mot de passe");
        println!("3. Générer un mot de passe");
        println!("4. Exporter une sauvegarde chiffrée");
        println!("5. Quitter");

        let choice: String = Input::new()
            .with_prompt("Choix")
            .interact_text()?;

        match choice.as_str() {
            "1" => {
                let site: String = Input::new()
                    .with_prompt("Site")
                    .interact_text()?;
                let username: String = Input::new()
                    .with_prompt("Nom d'utilisateur")
                    .interact_text()?;

                let generate = Confirm::new()
                    .with_prompt("Voulez-vous générer un mot de passe sécurisé?")
                    .default(true)
                    .interact()?;

                let password = if generate {
                    let length: String = Input::new()
                        .with_prompt("Longueur du mot de passe")
                        .default("20".into())
                        .interact_text()?;
                    let length = length.parse::<usize>()?;
                    pm.generate_password(length)
                } else {
                    Password::new()
                        .with_prompt("Mot de passe")
                        .with_confirmation("Confirmez le mot de passe", "Les mots de passe ne correspondent pas")
                        .interact()?
                };

                match pm.add_password(&site, &username, &password) {
                    Ok(_) => {
                        println!("\n✅ Mot de passe ajouté avec succès!");
                        if generate {
                            println!("📋 Votre mot de passe: {}", password);
                            println!("⚠️  Copiez-le maintenant - il ne sera plus affiché en clair");
                        }
                    },
                    Err(e) => println!("❌ Erreur: {}", e),
                }
            }
            "2" => {
                let site: String = Input::new()
                    .with_prompt("Site")
                    .interact_text()?;
                let username: String = Input::new()
                    .with_prompt("Nom d'utilisateur")
                    .interact_text()?;
                
                match pm.get_password(&site, &username) {
                    Ok(password) => {
                        println!("\n🔐 Mot de passe récupéré:");
                        println!("📋 {}", password);
                        println!("\n⚠️  Ce mot de passe ne sera affiché que pendant 30 secondes");
                        
                        // Timer de 30 secondes
                        std::thread::sleep(std::time::Duration::from_secs(30));
                        term.clear_screen()?;
                    },
                    Err(e) => println!("❌ Erreur: {}", e),
                }
            }
            "3" => {
                let length: String = Input::new()
                    .with_prompt("Longueur du mot de passe")
                    .default("20".into())
                    .interact_text()?;
                let length = length.parse::<usize>()?;
                
                let password = pm.generate_password(length);
                println!("\n🎲 Mot de passe généré: {}", password);
                println!("\nVoulez-vous l'enregistrer pour un site?");
                
                if Confirm::new()
                    .with_prompt("Enregistrer ce mot de passe?")
                    .default(false)
                    .interact()? 
                {
                    let site: String = Input::new()
                        .with_prompt("Site")
                        .interact_text()?;
                    let username: String = Input::new()
                        .with_prompt("Nom d'utilisateur")
                        .interact_text()?;
                    
                    match pm.add_password(&site, &username, &password) {
                        Ok(_) => println!("✅ Mot de passe enregistré avec succès!"),
                        Err(e) => println!("❌ Erreur: {}", e),
                    }
                }
            }
            "4" => {
                println!("\n📦 Export de la sauvegarde");
                match pm.export_encrypted_backup(Path::new("backup.json")) {
                    Ok(_) => println!("✅ Sauvegarde exportée avec succès!"),
                    Err(e) => println!("❌ Erreur lors de l'export: {}", e),
                }
            }
            "5" => {
                println!("\n👋 Au revoir!");
                break;
            }
            _ => println!("❌ Option invalide"),
        }
        
        println!("\nAppuyez sur Entrée pour continuer...");
        let _: String = Input::new().interact_text()?;
    }

    Ok(())
}