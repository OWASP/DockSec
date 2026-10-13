from docksec.redact import REDACTED, redact_content


def test_redacts_dockerfile_env_equals():
    content = "FROM python:3.12\nENV DB_PASSWORD=hunter2\nENV APP_NAME=myapp\n"
    redacted, count = redact_content(content)
    assert count == 1
    assert "hunter2" not in redacted
    assert f"DB_PASSWORD={REDACTED}" in redacted
    assert "APP_NAME=myapp" in redacted


def test_redacts_dockerfile_env_space_form():
    content = "ENV API_KEY abc123secretvalue\n"
    redacted, count = redact_content(content)
    assert count == 1
    assert "abc123secretvalue" not in redacted
    assert "API_KEY" in redacted


def test_redacts_arg_and_multiple_pairs():
    content = "ARG GITHUB_TOKEN=ghx123\nENV A=1 SECRET_KEY=s3cr3t B=2\n"
    redacted, count = redact_content(content)
    assert count == 2
    assert "ghx123" not in redacted
    assert "s3cr3t" not in redacted
    assert "A=1" in redacted and "B=2" in redacted


def test_redacts_compose_environment_styles():
    content = (
        "services:\n"
        "  db:\n"
        "    environment:\n"
        "      - MYSQL_ROOT_PASSWORD=secret\n"
        "      POSTGRES_PASSWORD: alsosecret\n"
    )
    redacted, count = redact_content(content)
    assert count == 2
    assert "secret" not in redacted.replace(REDACTED, "")


def test_leaves_interpolations_alone():
    content = "ENV DB_PASSWORD=${DB_PASSWORD}\n"
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_redacts_value_shaped_secrets_regardless_of_key():
    content = "RUN aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\n"
    redacted, count = redact_content(content)
    assert count >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted


def test_redacts_private_key_block():
    content = (
        "COPY key.pem /app\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    redacted, count = redact_content(content)
    assert count == 1
    assert "MIIEpAIBAAKCAQEA" not in redacted


def test_redacts_password_in_url_credentials():
    content = (
        "ENV DATABASE_URL=postgres://admin:s3cr3tPass@db:5432/app\n"
        "ENV REDIS_URL=redis://:mypassword@cache:6379/0\n"
        '      - "AMQP_URL=amqp://user:rabbitpw@broker:5672/"\n'
        "ENV MONGO_URI mongodb://root:supersecret@mongo:27017\n"
    )
    redacted, count = redact_content(content)
    assert count == 4
    for secret in ("s3cr3tPass", "mypassword", "rabbitpw", "supersecret"):
        assert secret not in redacted
    # Scheme, user, and host stay visible so the model can still flag it.
    assert f"postgres://admin:{REDACTED}@db:5432/app" in redacted
    assert f"redis://:{REDACTED}@cache:6379/0" in redacted


def test_leaves_url_without_password_alone():
    content = (
        "ENV APP_URL=https://example.com/health\n" "ENV HOST=postgres://db:5432/app\n"
    )
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_no_secrets_no_change():
    content = "FROM alpine:3.19\nRUN apk add --no-cache curl\nUSER nobody\n"
    redacted, count = redact_content(content)
    assert count == 0
    assert redacted == content


def test_redacts_password_in_url_query_string():
    # Credentials in URL query params (JDBC / Spring datasource URLs) are the
    # same threat as userinfo creds, but the outer key is not secret-looking.
    content = (
        "ENV SPRING_DATASOURCE_URL="
        "jdbc:postgresql://db:5432/app?user=sa&password=Sup3rSecret\n"
    )
    redacted, count = redact_content(content)
    assert count == 1
    assert "Sup3rSecret" not in redacted
    # Non-secret parts of the URL stay visible so the model can still flag it.
    assert "jdbc:postgresql://db:5432/app?user=sa" in redacted


def test_redacts_password_in_connection_string_fields():
    # Semicolon-delimited connection strings (.NET/JDBC) embed the password in
    # a field whose outer key (ConnectionStrings__Default) is not secret-looking.
    content = (
        "ENV ConnectionStrings__Default="
        "Server=db;Database=app;User Id=sa;Password=P@ssw0rd123;\n"
        '      - "CS=Server=db;Password=QuotedSecret999;"\n'
    )
    redacted, count = redact_content(content)
    assert count == 2
    for secret in ("P@ssw0rd123", "QuotedSecret999"):
        assert secret not in redacted
    # Host/user context is preserved.
    assert "Server=db" in redacted and "User Id=sa" in redacted


def test_embedded_pass_leaves_interpolations_and_plain_env_alone():
    # The embedded pass must not fire on interpolations or double-count a
    # top-level, space-delimited secret assignment already handled above.
    content = (
        "ENV DB_PASSWORD=${DB_PASSWORD}\n"
        "ENV A=1 SECRET_KEY=s3cr3t B=2\n"
        "ENV JDBC=jdbc:postgresql://db/app?password=${DB_PASSWORD}\n"
    )
    redacted, count = redact_content(content)
    # Only SECRET_KEY on line 2 is a real secret; interpolations are untouched.
    assert count == 1
    assert "s3cr3t" not in redacted
    assert "${DB_PASSWORD}" in redacted
    assert "A=1" in redacted and "B=2" in redacted
