# Quick Start

Get started with fnox in 5 minutes.

## 1. Initialize fnox

```bash
cd your-project
fnox init
```

This creates a `fnox.toml` configuration file.

## 2. Set a Secret

```bash
# Set a secret (prompts for value)
fnox set DATABASE_URL

# Or provide the value directly
fnox set DATABASE_URL "postgresql://localhost/mydb"
```

By default, secrets are stored as plain text defaults. For encryption, see the next section.

## 3. Get a Secret

```bash
fnox get DATABASE_URL
```

## 4. Run Commands with Secrets

```bash
# Secrets are loaded as environment variables
fnox exec -- npm start
fnox exec -- python app.py
fnox exec -- ./my-script.sh
```

## 5. Enable Shell Integration (Optional)

Automatically load secrets when you `cd` into a directory:

```bash
# Enable for your shell
eval "$(fnox activate bash)"  # or zsh, fish

# Add to your shell profile for persistence
echo 'eval "$(fnox activate bash)"' >> ~/.bashrc
```

Now secrets auto-load:

```bash
~/projects $ cd my-app
fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET
~/projects/my-app $
```

## Add Encryption (Recommended)

For production use, encrypt your secrets:

### Using age encryption

```bash
# 1. Generate an age key
age-keygen -o ~/.config/fnox/age.txt

# 2. Get your public key
grep "public key:" ~/.config/fnox/age.txt
# Output: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# 3. Configure the age provider in fnox.toml
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

# 4. Set your decryption key
export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")

# 5. Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider age
```

The secret is now encrypted in `fnox.toml` and safe to commit to git!

## Next Steps

- [How It Works](/guide/how-it-works) - Understand fnox's architecture
- [Providers](/providers/overview) - Explore all available providers
- [Shell Integration](/guide/shell-integration) - Deep dive into shell integration
- [Real-World Example](/guide/real-world-example) - See a complete setup with multiple environments
