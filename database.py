import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "amancheck.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
    )
    connection.row_factory = sqlite3.Row
    return connection


def add_missing_columns(connection):
    """
    إضافة الأعمدة الجديدة تلقائيًا إلى قاعدة البيانات القديمة.
    لذلك لا تحتاجين حذف amancheck.db.
    """

    existing_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(scans)"
        ).fetchall()
    }

    migrations = {
        "domain_age_days":
            "INTEGER",
    }

    for column_name, column_type in migrations.items():
        if column_name not in existing_columns:
            connection.execute(
                f"""
                ALTER TABLE scans
                ADD COLUMN {column_name}
                {column_type}
                """
            )


def create_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_url TEXT NOT NULL,
                final_url TEXT,
                page_title TEXT,
                domain_age_days INTEGER,
                url_score INTEGER NOT NULL DEFAULT 0,
                content_score INTEGER NOT NULL DEFAULT 0,
                credential_abuse INTEGER NOT NULL DEFAULT 0,
                data_destination INTEGER NOT NULL DEFAULT 0,
                social_engineering INTEGER NOT NULL DEFAULT 0,
                suspicious_behavior INTEGER NOT NULL DEFAULT 0,
                context_inconsistency INTEGER NOT NULL DEFAULT 0,
                has_password INTEGER NOT NULL DEFAULT 0,
                has_otp INTEGER NOT NULL DEFAULT 0,
                has_identity INTEGER NOT NULL DEFAULT 0,
                has_card INTEGER NOT NULL DEFAULT 0,
                has_cvv INTEGER NOT NULL DEFAULT 0,
                has_expiry INTEGER NOT NULL DEFAULT 0,
                redirect_count INTEGER NOT NULL DEFAULT 0,
                iframe_count INTEGER NOT NULL DEFAULT 0,
                hidden_inputs_count INTEGER NOT NULL DEFAULT 0,
                hidden_forms_count INTEGER NOT NULL DEFAULT 0,
                rule_score INTEGER NOT NULL DEFAULT 0,
                ai_score INTEGER,
                final_score INTEGER NOT NULL DEFAULT 0,
                level TEXT NOT NULL,
                classification TEXT NOT NULL
                    DEFAULT 'pending_review',
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        add_missing_columns(
            connection
        )


def save_scan(scan):
    columns = [
        "original_url",
        "final_url",
        "page_title",
        "domain_age_days",
        "url_score",
        "content_score",
        "credential_abuse",
        "data_destination",
        "social_engineering",
        "suspicious_behavior",
        "context_inconsistency",
        "has_password",
        "has_otp",
        "has_identity",
        "has_card",
        "has_cvv",
        "has_expiry",
        "redirect_count",
        "iframe_count",
        "hidden_inputs_count",
        "hidden_forms_count",
        "rule_score",
        "ai_score",
        "final_score",
        "level",
        "classification",
    ]

    values = [
        scan.get(column)
        for column in columns
    ]

    placeholders = ", ".join(
        "?"
        for _ in columns
    )

    with get_connection() as connection:
        cursor = connection.execute(
            f"""
            INSERT INTO scans (
                {", ".join(columns)}
            )
            VALUES ({placeholders})
            """,
            values,
        )

        return int(
            cursor.lastrowid
        )


def update_classification(
    scan_id,
    classification,
):
    allowed = {
        "pending_review",
        "legitimate",
        "suspicious",
    }

    if classification not in allowed:
        raise ValueError(
            "Invalid classification"
        )

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE scans
            SET classification = ?
            WHERE id = ?
            """,
            (
                classification,
                scan_id,
            ),
        )
