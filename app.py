from flask import Flask, jsonify, render_template, request
from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError
)
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import socket
import requests

from database import create_database, save_scan
from ai_model import predict_ai_score, combine_rule_and_ai


app = Flask(__name__)
create_database()


# =========================================================
# إعدادات النظام
# =========================================================

# وزن تحليل شكل الرابط
URL_WEIGHT = 0.15

# وزن تحليل محتوى وسلوك الصفحة
CONTENT_WEIGHT = 0.85

# اجعليها True أثناء فحص الصفحات المحلية مثل 127.0.0.1
# عند نشر المشروع على الإنترنت غيّريها إلى False
ALLOW_PRIVATE_URLS = True

# الحد الأعلى للنص الذي سنحلله
MAX_TEXT_LENGTH = 100_000


# =========================================================
# وظائف مساعدة
# =========================================================

def normalize_hostname(hostname):
    """
    توحيد شكل اسم الدومين.
    """

    hostname = (hostname or "").lower().strip(".")

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def is_ip_address(hostname):
    """
    التحقق هل الرابط يستخدم عنوان IP بدل الدومين.
    """

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def is_private_target(hostname):
    """
    التحقق من أن الرابط لا يشير إلى شبكة داخلية.

    هذا مهم عند نشر المشروع حتى لا يستطيع المستخدم
    استخدام النظام للوصول إلى خدمات داخلية في السيرفر.
    """

    hostname = normalize_hostname(hostname)

    if hostname == "localhost":
        return True

    try:
        addresses = socket.getaddrinfo(hostname, None)

        for address in addresses:
            ip_text = address[4][0]
            ip = ipaddress.ip_address(ip_text)

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return True

    except Exception:
        return False

    return False


def get_base_domain(hostname):
    """
    استخراج تقريبي للدومين الأساسي.

    مثال:
    pay.example.com -> example.com
    shop.example.com.sa -> example.com.sa
    """

    hostname = normalize_hostname(hostname)

    if hostname in {"localhost", "127.0.0.1"}:
        return hostname

    parts = hostname.split(".")

    multi_part_suffixes = {
        "com.sa",
        "net.sa",
        "org.sa",
        "edu.sa",
        "gov.sa",
        "co.uk",
        "com.au"
    }

    if len(parts) >= 3:
        suffix = ".".join(parts[-2:])

        if suffix in multi_part_suffixes:
            return ".".join(parts[-3:])

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


def build_field_text(field):
    """
    دمج خصائص حقل الإدخال في نص واحد لتحليله.
    """

    return " ".join([
        str(field.get("tag", "")),
        str(field.get("type", "")),
        str(field.get("name", "")),
        str(field.get("id", "")),
        str(field.get("placeholder", "")),
        str(field.get("autocomplete", "")),
        str(field.get("aria_label", ""))
    ]).lower()



# =========================================================
# حساب عمر الدومين باستخدام RDAP
# =========================================================

IANA_RDAP_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)


@lru_cache(maxsize=1)
def load_rdap_bootstrap():
    """
    تحميل قائمة خوادم RDAP الرسمية من IANA.
    يتم حفظها في الذاكرة حتى لا نعيد تحميلها مع كل فحص.
    """

    response = requests.get(
        IANA_RDAP_BOOTSTRAP_URL,
        timeout=8,
        headers={
            "User-Agent": "AmanCheck/1.0"
        },
    )

    response.raise_for_status()

    return response.json()


def get_rdap_server(domain):
    """
    تحديد خادم RDAP المناسب لامتداد الدومين.

    مثال:
    example.com -> خادم RDAP الخاص بامتداد com
    """

    if "." not in domain:
        return None

    tld = domain.rsplit(".", 1)[-1].lower()

    bootstrap_data = load_rdap_bootstrap()

    for service in bootstrap_data.get(
        "services",
        []
    ):
        if len(service) < 2:
            continue

        supported_tlds = {
            str(item).lower()
            for item in service[0]
        }

        servers = service[1]

        if tld in supported_tlds and servers:
            return servers[0]

    return None


def parse_rdap_datetime(value):
    """
    تحويل تاريخ RDAP إلى datetime مع دعم Z.
    """

    if not value:
        return None

    normalized = value.strip().replace(
        "Z",
        "+00:00"
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


@lru_cache(maxsize=512)
def get_domain_age_days(hostname):
    """
    إرجاع عمر الدومين بالأيام.

    إذا لم تتوفر المعلومة أو فشل الاتصال:
    يرجع None ولا يضيف النظام أي نقاط خطر.
    """

    base_domain = get_base_domain(
        hostname
    )

    if base_domain in {
        "",
        "localhost",
        "127.0.0.1",
    }:
        return None

    try:
        rdap_server = get_rdap_server(
            base_domain
        )

        if not rdap_server:
            return None

        query_url = (
            rdap_server.rstrip("/")
            + "/domain/"
            + base_domain
        )

        response = requests.get(
            query_url,
            timeout=10,
            allow_redirects=True,
            headers={
                "Accept":
                    "application/rdap+json",
                "User-Agent":
                    "AmanCheck/1.0",
            },
        )

        response.raise_for_status()

        rdap_data = response.json()

        creation_date = None

        # RDAP عادة يستخدم eventAction = registration.
        for event in rdap_data.get(
            "events",
            []
        ):
            action = str(
                event.get(
                    "eventAction",
                    ""
                )
            ).lower()

            if action in {
                "registration",
                "registered",
                "creation",
            }:
                creation_date = event.get(
                    "eventDate"
                )
                break

        created_at = parse_rdap_datetime(
            creation_date
        )

        if created_at is None:
            return None

        age_days = (
            datetime.now(timezone.utc)
            - created_at
        ).days

        return max(
            age_days,
            0
        )

    except requests.RequestException as error:
        print(
            "Domain age network error:",
            repr(error)
        )
        return None

    except Exception as error:
        print(
            "Domain age lookup error:",
            repr(error)
        )
        return None


# =========================================================
# تحليل شكل الرابط
# =========================================================

def analyze_url(url):
    """
    تحليل شكل الرابط وإرجاع درجة من 100.

    هذه الدرجة ستأخذ 15% من نتيجة القواعد.
    """

    parsed_url = urlparse(url)

    hostname = normalize_hostname(parsed_url.hostname)
    lower_url = url.lower()

    domain_age_days = get_domain_age_days(
        hostname
    )

    score = 0
    reasons = []
    indicators = set()

    # -----------------------------------------------------
    # 1. عدم استخدام HTTPS
    # -----------------------------------------------------

    if parsed_url.scheme != "https":
        score += 20
        indicators.add("no_https")

        reasons.append(
            "الرابط لا يستخدم اتصال HTTPS مشفرًا"
        )

    # -----------------------------------------------------
    # 2. استخدام IP بدل اسم دومين
    # -----------------------------------------------------

    if (
        is_ip_address(hostname)
        and hostname != "127.0.0.1"
    ):
        score += 20
        indicators.add("ip_address")

        reasons.append(
            "الرابط يستخدم عنوان IP بدل اسم دومين"
        )

    # -----------------------------------------------------
    # 3. روابط مختصرة
    # -----------------------------------------------------

    shortener_domains = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "is.gd",
        "shorturl.at"
    }

    if hostname in shortener_domains:
        score += 20
        indicators.add("short_url")

        reasons.append(
            "الرابط مختصر ويخفي الوجهة الأصلية"
        )

    # -----------------------------------------------------
    # 4. وجود رمز @
    # -----------------------------------------------------

    if "@" in url:
        score += 20
        indicators.add("at_symbol")

        reasons.append(
            "الرابط يحتوي على رمز @ بصورة غير معتادة"
        )

    # -----------------------------------------------------
    # 5. Punycode
    # -----------------------------------------------------

    if "xn--" in hostname:
        score += 20
        indicators.add("punycode")

        reasons.append(
            "الدومين يستخدم ترميزًا قد يخفي تشابه الحروف"
        )

    # -----------------------------------------------------
    # 6. تعقيد اسم الدومين
    # -----------------------------------------------------

    dash_count = hostname.count("-")

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    subdomain_count = max(
        len(hostname.split(".")) - 2,
        0
    )

    if dash_count >= 3:
        score += 8
        indicators.add("many_dashes")

        reasons.append(
            "اسم الدومين يحتوي على شرطات كثيرة"
        )

    if (
        hostname not in {"localhost", "127.0.0.1"}
        and digit_count >= 4
    ):
        score += 7
        indicators.add("many_digits")

        reasons.append(
            "اسم الدومين يحتوي على أرقام كثيرة"
        )

    if subdomain_count >= 4:
        score += 8
        indicators.add("many_subdomains")

        reasons.append(
            "الرابط يحتوي على عدد كبير من النطاقات الفرعية"
        )

    if len(hostname) > 45:
        score += 7
        indicators.add("long_domain")

        reasons.append(
            "اسم الدومين طويل بصورة غير معتادة"
        )

    # -----------------------------------------------------
    # 7. كلمات مريبة داخل الرابط
    # -----------------------------------------------------

    suspicious_words = {
        "verify",
        "update",
        "unlock",
        "confirm",
        "password",
        "account",
        "login"
    }

    if any(
        word in lower_url
        for word in suspicious_words
    ):
        score += 10
        indicators.add("suspicious_words")

        reasons.append(
            "الرابط يحتوي على كلمات مرتبطة بالتحقق أو الحساب"
        )

    # -----------------------------------------------------
    # 8. عمر الدومين
    # -----------------------------------------------------

    if domain_age_days is not None:

        if domain_age_days <= 7:
            score += 25
            indicators.add(
                "very_new_domain"
            )

            reasons.append(
                "الدومين مسجل منذ أقل من أسبوع"
            )

        elif domain_age_days <= 30:
            score += 20
            indicators.add(
                "new_domain"
            )

            reasons.append(
                "الدومين مسجل منذ أقل من شهر"
            )

        elif domain_age_days <= 180:
            score += 10
            indicators.add(
                "young_domain"
            )

            reasons.append(
                "عمر الدومين أقل من ستة أشهر"
            )

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "indicators": indicators,
        "hostname": hostname,
        "domain_age_days": domain_age_days
    }


# =========================================================
# استخراج بيانات الصفحة باستخدام Playwright
# =========================================================

def extract_page_data(url):
    """فتح الصفحة واستخراج البيانات مع تتبع التحويلات بثبات أكبر."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=False,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
            )
        )
        page = context.new_page()
        navigation_urls = []
        http_redirect_count = 0

        def track_navigation(request):
            nonlocal http_redirect_count
            if request.is_navigation_request():
                navigation_urls.append(request.url)
                if request.redirected_from is not None:
                    http_redirect_count += 1

        page.on("request", track_navigation)
        page.goto(url, wait_until="domcontentloaded", timeout=20_000)
        page.wait_for_timeout(5000)
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        title = page.title() or ""
        final_url = page.url
        texts, inputs, forms = [], [], []
        iframe_count = max(len(page.frames) - 1, 0)

        for frame in page.frames:
            try:
                text = frame.locator("body").inner_text(timeout=3000)
                if text:
                    texts.append(text)
            except Exception:
                pass
            try:
                inputs.extend(frame.locator("input, textarea, select").evaluate_all("""
                    elements => elements.map(element => ({
                        tag: element.tagName || "",
                        type: element.type || "",
                        name: element.name || "",
                        id: element.id || "",
                        placeholder: element.placeholder || "",
                        autocomplete: element.autocomplete || "",
                        aria_label: element.getAttribute("aria-label") || "",
                        hidden: element.type === "hidden" || element.hidden === true || element.offsetParent === null
                    }))
                """))
            except Exception:
                pass
            try:
                forms.extend(frame.locator("form").evaluate_all("""
                    forms => forms.map(form => ({
                        action: form.action || "",
                        method: form.method || "",
                        hidden: form.hidden === true || form.offsetParent === null
                    }))
                """))
            except Exception:
                pass

        hidden_inputs_count = sum(1 for field in inputs if field.get("hidden"))
        hidden_forms_count = sum(1 for form in forms if form.get("hidden"))

        unique_navigation_urls = []
        for navigation_url in navigation_urls:
            if not unique_navigation_urls or navigation_url != unique_navigation_urls[-1]:
                unique_navigation_urls.append(navigation_url)

        navigation_redirect_count = max(len(unique_navigation_urls) - 1, 0)
        redirect_count = max(http_redirect_count, navigation_redirect_count)
        try:
            meta_refresh_count = page.locator('meta[http-equiv="refresh" i]').count()
        except Exception:
            meta_refresh_count = 0
        if meta_refresh_count > 0:
            redirect_count += 1

        print("-" * 60)
        print("Original URL:", url)
        print("Final URL:", final_url)
        print("Navigation URLs:", unique_navigation_urls)
        print("HTTP Redirects:", http_redirect_count)
        print("Navigation Redirects:", navigation_redirect_count)
        print("Meta Refresh:", meta_refresh_count)
        print("Final Redirect Count:", redirect_count)
        browser.close()

    page_text = " ".join(texts)[:MAX_TEXT_LENGTH].lower()
    return {
        "title": title,
        "final_url": final_url,
        "page_text": page_text,
        "inputs": inputs,
        "forms": forms,
        "redirect_count": redirect_count,
        "http_redirect_count": http_redirect_count,
        "navigation_redirect_count": navigation_redirect_count,
        "meta_refresh_count": meta_refresh_count,
        "navigation_urls": unique_navigation_urls,
        "iframe_count": iframe_count,
        "hidden_inputs_count": hidden_inputs_count,
        "hidden_forms_count": hidden_forms_count
    }


# =========================================================
# اكتشاف أنواع البيانات في الصفحة
# =========================================================

def detect_fields(page_text, inputs):
    """
    اكتشاف البيانات المطلوبة في الصفحة.

    وجود البطاقة وCVV وتاريخ الانتهاء طبيعي
    ولا يرفع درجة الخطر بمفرده.
    """

    detected = set()

    # -----------------------------------------------------
    # الاكتشاف من خصائص حقول الإدخال
    # -----------------------------------------------------

    for field in inputs:

        field_text = build_field_text(field)

        if (
            field.get("type") == "password"
            or "password" in field_text
            or "كلمة المرور" in field_text
        ):
            detected.add("password")

        if any(
            phrase in field_text
            for phrase in {
                "otp",
                "one time password",
                "verification code",
                "رمز التحقق",
                "رمز التأكيد"
            }
        ):
            detected.add("otp")

        if any(
            phrase in field_text
            for phrase in {
                "national id",
                "national_id",
                "identity number",
                "id number",
                "رقم الهوية",
                "الهوية الوطنية"
            }
        ):
            detected.add("identity")

        if any(
            phrase in field_text
            for phrase in {
                "card number",
                "card_number",
                "cc-number",
                "رقم البطاقة"
            }
        ):
            detected.add("card")

        if any(
            phrase in field_text
            for phrase in {
                "cvv",
                "cvc",
                "cc-csc",
                "security code",
                "رمز الأمان"
            }
        ):
            detected.add("cvv")

        if any(
            phrase in field_text
            for phrase in {
                "expiry",
                "expiration",
                "cc-exp",
                "تاريخ الانتهاء",
                "شهر / سنة"
            }
        ):
            detected.add("expiry")

    # -----------------------------------------------------
    # الاكتشاف من النص الظاهر
    # -----------------------------------------------------

    text_patterns = {
        "password": [
            "password",
            "كلمة المرور"
        ],

        "otp": [
            "one time password",
            "verification code",
            "رمز التحقق",
            "رمز التأكيد"
        ],

        "identity": [
            "national id",
            "identity number",
            "رقم الهوية",
            "الهوية الوطنية"
        ],

        "card": [
            "card number",
            "رقم البطاقة",
            "بيانات البطاقة"
        ],

        "cvv": [
            "cvv",
            "cvc",
            "security code",
            "رمز الأمان"
        ],

        "expiry": [
            "expiry",
            "expiration date",
            "تاريخ الانتهاء",
            "شهر / سنة"
        ]
    }

    for field_name, patterns in text_patterns.items():

        if any(
            pattern in page_text
            for pattern in patterns
        ):
            detected.add(field_name)

    return detected


# =========================================================
# تحليل محتوى وسلوك الصفحة
# =========================================================

def analyze_page(
    original_url,
    page_data,
    url_analysis
):
    """
    تحليل الصفحة عبر خمسة محاور:

    1. Credential Abuse      30
    2. Data Destination      25
    3. Social Engineering    15
    4. Suspicious Behavior   15
    5. Context Inconsistency 15

    المجموع = 100
    """

    title = page_data["title"]
    page_text = page_data["page_text"]
    final_url = page_data["final_url"]
    inputs = page_data["inputs"]
    forms = page_data["forms"]

    combined_text = (
        title + " " + page_text
    ).lower()

    detected_fields = detect_fields(
        combined_text,
        inputs
    )

    has_payment_fields = any(
        field in detected_fields
        for field in {
            "card",
            "cvv",
            "expiry"
        }
    )

    # =====================================================
    # المحور الأول: Credential Abuse
    # الحد الأعلى 30
    # =====================================================

    credential_score = 0
    credential_reasons = []

    # بطاقة وCVV وانتهاء فقط = طبيعي
    # OTP وحده لا يضيف نقاطًا

    if (
        has_payment_fields
        and "password" in detected_fields
    ):
        credential_score += 20

        credential_reasons.append(
            "صفحة الدفع تطلب كلمة مرور الحساب"
        )

    if (
        has_payment_fields
        and "password" in detected_fields
        and "otp" in detected_fields
    ):
        credential_score += 10

        credential_reasons.append(
            "صفحة الدفع تجمع كلمة المرور مع رمز التحقق"
        )

    credential_score = min(
        credential_score,
        30
    )

    # =====================================================
    # المحور الثاني: Data Destination
    # الحد الأعلى 25
    # =====================================================

    destination_score = 0
    destination_reasons = []

    final_hostname = normalize_hostname(
        urlparse(final_url).hostname
    )

    final_base_domain = get_base_domain(
        final_hostname
    )

    external_actions = []

    for form in forms:

        action = form.get("action", "").strip()

        if not action:
            continue

        full_action = urljoin(
            final_url,
            action
        )

        action_hostname = normalize_hostname(
            urlparse(full_action).hostname
        )

        action_base_domain = get_base_domain(
            action_hostname
        )

        if (
            action_base_domain
            and final_base_domain
            and action_base_domain != final_base_domain
        ):
            external_actions.append(
                action_hostname
            )

    account_sensitive_fields = {
        field
        for field in detected_fields
        if field in {
            "password",
            "otp",
            "identity"
        }
    }

    if external_actions:

        if account_sensitive_fields:
            destination_score = 25

            destination_reasons.append(
                "الصفحة ترسل بيانات حساسة إلى دومين مختلف"
            )

        else:
            destination_score = 8

            destination_reasons.append(
                "نموذج الصفحة يرسل البيانات إلى دومين خارجي"
            )

    destination_score = min(
        destination_score,
        25
    )

    # =====================================================
    # المحور الثالث: Social Engineering
    # الحد الأعلى 15
    # =====================================================

    social_score = 0
    social_reasons = []

    urgency_phrases = {
        "urgent",
        "immediately",
        "within 24 hours",
        "account will be suspended",
        "account will be blocked",
        "عاجل",
        "فوراً",
        "فورا",
        "خلال 24 ساعة",
        "سيتم إيقاف حسابك",
        "سيتم تعليق حسابك",
        "سيتم حظر حسابك"
    }

    urgency_matches = [
        phrase
        for phrase in urgency_phrases
        if phrase in combined_text
    ]

    if urgency_matches:
        social_score += 5

        social_reasons.append(
            "الصفحة تستخدم عبارات استعجال"
        )

    threat_phrases = {
        "account will be suspended",
        "account will be blocked",
        "سيتم إيقاف حسابك",
        "سيتم تعليق حسابك",
        "سيتم حظر حسابك"
    }

    has_threat = any(
        phrase in combined_text
        for phrase in threat_phrases
    )

    if has_threat:
        social_score += 5

        social_reasons.append(
            "الصفحة تهدد بإيقاف أو حظر الحساب"
        )

    if (
        urgency_matches
        and account_sensitive_fields
    ):
        social_score += 5

        social_reasons.append(
            "الاستعجال متزامن مع طلب بيانات حساسة"
        )

    social_score = min(
        social_score,
        15
    )

    # =====================================================
    # المحور الرابع: Suspicious Behavior
    # الحد الأعلى 15
    # =====================================================

    behavior_score = 0
    behavior_reasons = []

    redirect_count = page_data[
        "redirect_count"
    ]

    hidden_inputs_count = page_data[
        "hidden_inputs_count"
    ]

    hidden_forms_count = page_data[
        "hidden_forms_count"
    ]

    # التحويل الواحد أو اثنان طبيعي
    if redirect_count >= 3:
        behavior_score += 5

        behavior_reasons.append(
            "الرابط مر بعدة تحويلات متتالية"
        )

    # الحقول المخفية شائعة في بوابات الدفع الشرعية.
    # لا ترفع الخطر إلا عند اجتماعها مع سلوك آخر غير معتاد.
    if (
        hidden_inputs_count >= 12
        and (hidden_forms_count >= 1 or external_actions)
    ):
        behavior_score += 5
        behavior_reasons.append(
            "الصفحة تجمع عددًا كبيرًا من الحقول المخفية مع سلوك إضافي غير معتاد"
        )

    if hidden_forms_count >= 1 and external_actions:
        behavior_score += 5
        behavior_reasons.append(
            "الصفحة تحتوي نموذجًا مخفيًا يرسل البيانات إلى دومين خارجي"
        )

    behavior_score = min(
        behavior_score,
        15
    )

    # =====================================================
    # المحور الخامس: Context Inconsistency
    # الحد الأعلى 15
    # =====================================================

    context_score = 0
    context_reasons = []

    # كلمة المرور غير منطقية غالبًا داخل نموذج الدفع
    if (
        has_payment_fields
        and "password" in detected_fields
    ):
        context_score += 8

        context_reasons.append(
            "صفحة الدفع تطلب بيانات دخول غير معتادة"
        )

    # جمع الهوية مع كلمة المرور وبيانات البطاقة
    unusual_collection = {
        "card",
        "identity",
        "password"
    }.issubset(detected_fields)

    if unusual_collection:
        context_score += 7

        context_reasons.append(
            "الصفحة تجمع بيانات الدفع والهوية وكلمة المرور"
        )

    context_score = min(
        context_score,
        15
    )

    # =====================================================
    # Page Score
    # =====================================================

    page_score = (
        credential_score
        + destination_score
        + social_score
        + behavior_score
        + context_score
    )

    page_score = min(
        page_score,
        100
    )

    reasons = (
        credential_reasons
        + destination_reasons
        + social_reasons
        + behavior_reasons
        + context_reasons
    )

    breakdown = {
        "credential_abuse": credential_score,
        "data_destination": destination_score,
        "social_engineering": social_score,
        "suspicious_behavior": behavior_score,
        "context_inconsistency": context_score
    }

    return {
        "score": page_score,
        "reasons": reasons,
        "breakdown": breakdown,
        "detected_fields": detected_fields
    }


# =========================================================
# الصفحة الرئيسية
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# API الفحص
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get(
        "url",
        ""
    ).strip()

    # -----------------------------------------------------
    # التحقق من الرابط
    # -----------------------------------------------------

    parsed_url = urlparse(url)

    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
    ):
        return jsonify({
            "success": False,
            "message": (
                "الرجاء إدخال رابط صحيح يبدأ "
                "بـ http:// أو https://"
            )
        }), 400

    hostname = normalize_hostname(
        parsed_url.hostname
    )

    # حماية عند النشر
    if (
        not ALLOW_PRIVATE_URLS
        and is_private_target(hostname)
    ):
        return jsonify({
            "success": False,
            "message": (
                "لا يمكن فحص عناوين "
                "الشبكات الداخلية"
            )
        }), 400

    try:
        # -------------------------------------------------
        # تحليل الرابط
        # -------------------------------------------------

        url_analysis = analyze_url(url)

        # -------------------------------------------------
        # فتح الصفحة واستخراج البيانات
        # -------------------------------------------------

        page_data = extract_page_data(url)

        # -------------------------------------------------
        # تحليل محتوى وسلوك الصفحة
        # -------------------------------------------------

        page_analysis = analyze_page(
            original_url=url,
            page_data=page_data,
            url_analysis=url_analysis
        )

        url_score = url_analysis["score"]
        content_score = page_analysis["score"]

        # =================================================
        # النتيجة النهائية
        # URL = 15%
        # Content = 85%
        # =================================================

        # نتيجة القواعد الحالية
        rule_score = round(
            (url_score * URL_WEIGHT)
            + (content_score * CONTENT_WEIGHT)
        )
        rule_score = max(0, min(rule_score, 100))

        # توقع الذكاء الاصطناعي من خصائص الرابط
        # المودل الحالي يحلل شكل الرابط فقط.
        # لا نمرر له التحويل الديناميكي حتى تبقى النتيجة مستقرة.
        ai_score = predict_ai_score(
            url=url,
            redirect_count=0
        )

        # النتيجة النهائية: 90% قواعد + 10% AI
        final_score = combine_rule_and_ai(
            rule_score=rule_score,
            ai_score=ai_score,
            rule_weight=0.90,
            ai_weight=0.10
        )

        # -------------------------------------------------
        # التصنيف
        # -------------------------------------------------

        if final_score < 21:
            level = "منخفض"
        elif final_score < 56:
            level = "متوسط"
        else:
            level = "مرتفع"

        # -------------------------------------------------
        # دمج الأسباب
        # -------------------------------------------------

        reasons = (
            url_analysis["reasons"]
            + page_analysis["reasons"]
        )

        if not reasons:
            reasons = [
                "لم يتم رصد مؤشرات خطر واضحة"
            ]

        # -------------------------------------------------
        # التوصية
        # -------------------------------------------------

        if level == "مرتفع":
            recommendation = (
                "تم رصد عدة مؤشرات خطر. "
                "لا ننصح بإدخال أي بيانات "
                "قبل التأكد من الجهة الرسمية."
            )

        elif level == "متوسط":
            recommendation = (
                "تم رصد مؤشرات تحتاج إلى التحقق. "
                "راجعي الدومين والجهة قبل المتابعة."
            )

        else:
            recommendation = (
                "لم يتم رصد مؤشرات خطر واضحة، "
                "لكن النتيجة لا تعني أن الموقع "
                "آمن بنسبة 100%."
            )

        # -------------------------------------------------
        # حفظ عملية الفحص في SQLite
        # -------------------------------------------------

        detected_fields = page_analysis["detected_fields"]
        breakdown = page_analysis["breakdown"]

        scan_record = {
            "original_url": url,
            "final_url": page_data["final_url"],
            "page_title": page_data["title"],
            "domain_age_days":
                url_analysis["domain_age_days"],
            "url_score": url_score,
            "content_score": content_score,
            "credential_abuse": breakdown["credential_abuse"],
            "data_destination": breakdown["data_destination"],
            "social_engineering": breakdown["social_engineering"],
            "suspicious_behavior": breakdown["suspicious_behavior"],
            "context_inconsistency": breakdown["context_inconsistency"],
            "has_password": int("password" in detected_fields),
            "has_otp": int("otp" in detected_fields),
            "has_identity": int("identity" in detected_fields),
            "has_card": int("card" in detected_fields),
            "has_cvv": int("cvv" in detected_fields),
            "has_expiry": int("expiry" in detected_fields),
            "redirect_count": page_data["redirect_count"],
            "iframe_count": page_data["iframe_count"],
            "hidden_inputs_count": page_data["hidden_inputs_count"],
            "hidden_forms_count": page_data["hidden_forms_count"],
            "rule_score": rule_score,
            "ai_score": ai_score,
            "final_score": final_score,
            "level": level,
            "classification": "pending_review"
        }

        scan_id = save_scan(scan_record)

        # -------------------------------------------------
        # طباعة النتائج للتجربة
        # -------------------------------------------------

        print("=" * 60)
        print("URL:", url)
        print(
            "Final URL:",
            page_data["final_url"]
        )
        print(
            "Detected fields:",
            page_analysis["detected_fields"]
        )
        print(
            "Page breakdown:",
            page_analysis["breakdown"]
        )
        print(
            "Domain Age Days:",
            url_analysis["domain_age_days"]
        )
        print("URL Score:", url_score)
        print("Content Score:", content_score)
        print("Rule Score:", rule_score)
        print("AI Score:", ai_score)
        print("Final Hybrid Score:", final_score)
        print("Level:", level)
        print("Reasons:", reasons)

        # -------------------------------------------------
        # إرسال النتيجة للواجهة
        # -------------------------------------------------

        return jsonify({
            "success": True,

            "url_score": url_score,

            "domain_age_days":
                url_analysis["domain_age_days"],

            "content_score": content_score,

            "final_score": final_score,

            "rule_score": rule_score,

            "ai_score": ai_score,

            "scan_id": scan_id,

            "level": level,

            "reasons": reasons,

            "recommendation": recommendation,

            "page_breakdown":
                page_analysis["breakdown"],

            "detected_fields": sorted(
                page_analysis["detected_fields"]
            ),

            "title": page_data["title"],

            "final_url": page_data["final_url"],
            "redirect_count": page_data["redirect_count"],
            "http_redirect_count": page_data["http_redirect_count"],
            "navigation_redirect_count": page_data["navigation_redirect_count"],
            "meta_refresh_count": page_data["meta_refresh_count"],
            "hidden_inputs_count": page_data["hidden_inputs_count"],
            "hidden_forms_count": page_data["hidden_forms_count"],
            "iframe_count": page_data["iframe_count"]
        })

    except PlaywrightTimeoutError:

        return jsonify({
            "success": False,
            "message": (
                "انتهت مهلة فتح الصفحة. "
                "قد تكون الصفحة بطيئة "
                "أو تمنع أدوات الفحص."
            )
        }), 504

    except Exception as error:

        print(
            "Scan error:",
            repr(error)
        )

        return jsonify({
            "success": False,
            "message": (
                "تعذر فتح الرابط "
                "أو تحليل محتوى الصفحة"
            )
        }), 500


# =========================================================
# تشغيل Flask
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)