# 🔒 Rust Secure Password Manager

Un gestionnaire de mots de passe sécurisé développé en Rust, offrant un chiffrement robuste et des fonctionnalités de sécurité avancées.

## ✨ Fonctionnalités

- Chiffrement fort avec ChaCha20-Poly1305
- Stockage sécurisé avec SQLite
- Protection contre les attaques par force brute
- Génération de mots de passe robustes
- Vérification d'intégrité via HMAC
- Sauvegarde chiffrée des données
- Interface en ligne de commande interactive
- Nettoyage automatique des anciennes données

## 🛡️ Mesures de Sécurité

- Utilisation d'Argon2 pour le hachage des mots de passe
- Protection contre la réutilisation des nonces
- Verrouillage temporaire après plusieurs tentatives échouées
- Longueur minimale imposée pour le mot de passe maître (12 caractères)
- Effacement automatique des données sensibles de la mémoire
- Horodatage des accès et modifications
- Vérification cryptographique de l'intégrité des données

## 🚀 Installation

### Prérequis

- Rust et Cargo (dernière version stable)
- SQLite 3

### Compilation

```bash
git clone https://github.com/your-username/rust-password-manager.git
cd rust-password-manager
cargo build --release
```

L'exécutable se trouvera dans `target/release/`.

## 📝 Utilisation

1. Lancez le programme :
```bash
./password-manager
```

2. Lors de la première utilisation, créez un mot de passe maître fort (minimum 12 caractères).

3. Utilisez le menu principal pour :
   - Ajouter des mots de passe
   - Récupérer des mots de passe existants
   - Générer des mots de passe sécurisés
   - Exporter une sauvegarde chiffrée

## 📦 Dépendances Principales

- `age`: Chiffrement X25519
- `argon2`: Hachage sécurisé des mots de passe
- `chacha20poly1305`: Chiffrement authentifié
- `rusqlite`: Interface SQLite
- `zeroize`: Effacement sécurisé de la mémoire
- `dialoguer`: Interface utilisateur interactive
- `serde`: Sérialisation/désérialisation

## ⚠️ Bonnes Pratiques de Sécurité

1. Choisissez un mot de passe maître fort et unique
2. Effectuez des sauvegardes régulières
3. Stockez les sauvegardes dans un endroit sûr
4. Ne partagez jamais votre mot de passe maître
5. Évitez d'utiliser des services cloud non chiffrés pour les sauvegardes

## 🔍 Tests

```bash
cargo test
```

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commit vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## ⚡ Performances

- Temps de démarrage rapide
- Utilisation mémoire optimisée
- Nettoyage automatique des anciennes données

## 🔜 Améliorations Futures

- Interface graphique
- Synchronisation chiffrée
- Import depuis d'autres gestionnaires
- Support des fichiers joints chiffrés
- Audit de sécurité automatisé
