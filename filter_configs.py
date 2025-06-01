import requests
import base64
import os
import re
import sys
import hashlib
import json
from datetime import datetime, timezone, timedelta

# --- ثابت‌های پیکربندی (بدون تغییر) ---
MIN_PERCENT25_COUNT = int(os.environ.get('MIN_PERCENT25_COUNT', 15))
MAX_CONFIG_LENGTH = int(os.environ.get('MAX_CONFIG_LENGTH', 1500))
KEYWORD = "i_love_"
DOUBLE_ENCODING_SEQUENCE = "%2525"
CONFIG_PREFIXES = (
    "vmess://", "vless://", "trojan://",
    "ss://", "ssr://", "tuic://", "hy2://"
)
REQUEST_TIMEOUT = 20
OUTPUT_DETAILS_DIR = "suspicious_config_details"
STATUS_DB_FILE = "link_update_status.json"
STALENESS_REPORT_FILE = "link_staleness_report.txt"

# --- توابع add_base64_padding, decode_subscription_content, check_config_suspicious, sanitize_url_for_filename (بدون تغییر) ---
def add_base64_padding(s: str) -> str:
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return s

def decode_subscription_content(content_bytes: bytes) -> tuple[str, bool]:
    text_content_from_bytes = ""
    was_base64_decoded = False
    try:
        text_payload_candidate = content_bytes.decode('utf-8')
        cleaned_b64_string = "".join(text_payload_candidate.split())
        if cleaned_b64_string and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", cleaned_b64_string):
            padded_b64_string = add_base64_padding(cleaned_b64_string)
            try:
                decoded_bytes_from_string = base64.b64decode(padded_b64_string)
                final_text_content_check = decoded_bytes_from_string.decode('utf-8')
                if '\n' in final_text_content_check or any(prefix in final_text_content_check for prefix in CONFIG_PREFIXES):
                    text_content_from_bytes = final_text_content_check
                    was_base64_decoded = True
                else:
                    text_content_from_bytes = text_payload_candidate
            except (base64.binascii.Error, UnicodeDecodeError):
                text_content_from_bytes = text_payload_candidate
        else:
            text_content_from_bytes = text_payload_candidate
    except UnicodeDecodeError:
        try:
            temp_str_for_padding = content_bytes.decode('ascii', errors='ignore').strip()
            padded_b64_bytes_direct = add_base64_padding(temp_str_for_padding).encode('ascii')
            decoded_bytes_direct = base64.b64decode(padded_b64_bytes_direct)
            text_content_from_bytes = decoded_bytes_direct.decode('utf-8')
            was_base64_decoded = True
        except Exception:
            text_content_from_bytes = content_bytes.decode('utf-8', errors='ignore')
    except Exception:
        text_content_from_bytes = content_bytes.decode('utf-8', errors='ignore')
    return text_content_from_bytes, was_base64_decoded

def check_config_suspicious(config_str: str) -> list[str]:
    reasons = []
    if KEYWORD.lower() in config_str.lower():
        reasons.append(f"حاوی کلمه کلیدی '{KEYWORD}' است")
    percent25_count = config_str.count("%25")
    if percent25_count >= MIN_PERCENT25_COUNT:
        reasons.append(f"تعداد '%25' ({percent25_count}) برابر یا بیشتر از {MIN_PERCENT25_COUNT} است")
    config_len = len(config_str)
    if config_len >= MAX_CONFIG_LENGTH:
        reasons.append(f"طول ({config_len}) برابر یا بیشتر از {MAX_CONFIG_LENGTH} است")
    if DOUBLE_ENCODING_SEQUENCE in config_str:
        reasons.append(f"حاوی دنباله کدگذاری دوگانه '{DOUBLE_ENCODING_SEQUENCE}' است")
    return reasons

def sanitize_url_for_filename(url_str: str) -> str:
    url_hash = hashlib.md5(url_str.encode('utf-8')).hexdigest()[:8]
    try:
        domain_part = re.match(r"https?://([^/]+)", url_str).group(1)
        safe_domain_part = re.sub(r'[^\w.-]', '_', domain_part)
        filename_base = f"{safe_domain_part}_{url_hash}"
    except AttributeError:
        filename_base = f"url_{url_hash}"
    return filename_base + ".txt"

# --- توابع load_status_db و save_status_db (بدون تغییر) ---
def load_status_db() -> dict:
    if os.path.exists(STATUS_DB_FILE):
        try:
            with open(STATUS_DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"هشدار: فایل {STATUS_DB_FILE} قابل خواندن نیست یا فرمت JSON نامعتبر دارد. یک فایل جدید ایجاد خواهد شد.")
        except Exception as e:
            print(f"هشدار: خطا در خواندن {STATUS_DB_FILE}: {e}. یک فایل جدید ایجاد خواهد شد.")
    return {}

def save_status_db(data: dict):
    try:
        with open(STATUS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"پایگاه داده وضعیت لینک‌ها در {STATUS_DB_FILE} ذخیره شد.")
    except Exception as e:
        print(f"خطا در ذخیره پایگاه داده وضعیت لینک‌ها ({STATUS_DB_FILE}): {e}")


def main(links_file_path: str, main_summary_report_file_path: str):
    suspicious_summary_data = []
    staleness_data_for_sorting = [] # لیستی از دیکشنری‌ها برای مرتب‌سازی

    status_db = load_status_db()
    current_run_time_utc = datetime.now(timezone.utc)

    os.makedirs(OUTPUT_DETAILS_DIR, exist_ok=True)
    # ... (بخش خواندن فایل لینک‌ها بدون تغییر) ...
    try:
        with open(links_file_path, 'r', encoding='utf-8') as f_links:
            urls = [line.strip() for line in f_links if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"خطا: فایل لینک‌ها در مسیر '{links_file_path}' یافت نشد.")
        sys.exit(1)
    except Exception as e:
        print(f"خطا در خواندن فایل لینک‌ها '{links_file_path}': {e}")
        sys.exit(1)


    for url in urls:
        print(f"درحال پردازش URL: {url}")
        url_status_info = status_db.get(url, {}) # اطلاعات قبلی این URL از پایگاه داده
        content_hash = None
        fetch_error = False
        status_message_for_staleness_report = ""
        sort_key_for_staleness = float('inf') # پیش‌فرض برای خطاها یا موارد نامشخص

        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            content_bytes = response.content
            content_hash = hashlib.md5(content_bytes).hexdigest()
        except requests.exceptions.RequestException as e:
            print(f"  خطا در دریافت محتوای URL {url}: {e}")
            fetch_error = True
        
        current_url_iso_timestamp = current_run_time_utc.isoformat()

        if fetch_error:
            last_changed_ts_str = url_status_info.get("last_changed_timestamp")
            if last_changed_ts_str:
                last_changed_dt = datetime.fromisoformat(last_changed_ts_str.replace('Z', '+00:00'))
                days_stale = (current_run_time_utc - last_changed_dt).days
                status_message_for_staleness_report = f"خطا در دریافت. آخرین به‌روزرسانی محتوا {days_stale} روز پیش بود. (آخرین تلاش برای بررسی: {current_run_time_utc.strftime('%Y-%m-%d')})"
                sort_key_for_staleness = days_stale # مرتب‌سازی بر اساس آخرین زمان موفق
            else:
                status_message_for_staleness_report = f"خطا در دریافت (لینک جدید یا بدون سابقه موفق). (آخرین تلاش برای بررسی: {current_run_time_utc.strftime('%Y-%m-%d')})"
                sort_key_for_staleness = float('inf') # در انتها قرار می‌گیرد
            url_status_info["last_checked_timestamp"] = current_url_iso_timestamp
        
        elif content_hash: # دریافت موفق
            last_known_hash = url_status_info.get("last_hash")
            
            if last_known_hash == content_hash: # محتوا تغییر نکرده
                last_changed_dt_str = url_status_info.get("last_changed_timestamp")
                if last_changed_dt_str: # باید همیشه وجود داشته باشد اگر last_known_hash معتبر است
                    last_changed_dt = datetime.fromisoformat(last_changed_dt_str.replace('Z', '+00:00'))
                    days_stale = (current_run_time_utc - last_changed_dt).days
                    status_message_for_staleness_report = f"{days_stale} روز از آخرین به‌روزرسانی محتوا گذشته است."
                    sort_key_for_staleness = days_stale
                else: # حالت غیرمحتمل: هش قبلی وجود دارد ولی تاریخ آخرین تغییر نه!
                    status_message_for_staleness_report = "امروز به‌روز شد (سابقه تاریخ تغییر ناقص بود)." # فرض می‌کنیم تازه است
                    sort_key_for_staleness = 0 # یا 1- اگر بخواهیم مانند "امروز آپدیت شد" رفتار کند
                    url_status_info["last_changed_timestamp"] = current_url_iso_timestamp # تاریخ تغییر را امروز ثبت می‌کنیم
            else: # محتوا تغییر کرده یا لینک جدید است
                if last_known_hash: # یعنی قبلا بوده و الان تغییر کرده
                    status_message_for_staleness_report = "امروز به‌روز شد (محتوا تغییر کرد)."
                    sort_key_for_staleness = -1 # بالاتر از لینک‌های 0 روزه
                else: # لینک جدید است
                    status_message_for_staleness_report = f"جدید - اولین بررسی موفق در {current_run_time_utc.strftime('%Y-%m-%d')}."
                    sort_key_for_staleness = -2 # بالاتر از همه
                url_status_info["last_hash"] = content_hash
                url_status_info["last_changed_timestamp"] = current_url_iso_timestamp
            
            url_status_info["last_checked_timestamp"] = current_url_iso_timestamp
        
        status_db[url] = url_status_info
        if status_message_for_staleness_report:
             staleness_data_for_sorting.append({
                 "url": url,
                 "message": status_message_for_staleness_report,
                 "sort_key": sort_key_for_staleness
             })

        # --- پردازش کانفیگ‌های مشکوک (بدون تغییر در منطق اصلی این بخش) ---
        if not fetch_error:
            text_content, _ = decode_subscription_content(content_bytes)
            config_lines = text_content.splitlines()
            suspicious_configs_count_for_url = 0
            current_url_suspicious_config_details_for_file = []
            unique_flagged_configs_in_this_url = set()

            for line_content in config_lines:
                config_str = line_content.strip()
                if not config_str or not any(config_str.startswith(prefix) for prefix in CONFIG_PREFIXES):
                    continue
                reasons = check_config_suspicious(config_str)
                if reasons:
                    suspicious_configs_count_for_url += 1
                    if config_str not in unique_flagged_configs_in_this_url:
                        detail = f"کانفیگ:\n{config_str}\nدلایل:\n"
                        for reason in reasons:
                            detail += f"  - {reason}\n"
                        detail += "----------------------------------------\n"
                        current_url_suspicious_config_details_for_file.append(detail)
                        unique_flagged_configs_in_this_url.add(config_str)
            if suspicious_configs_count_for_url > 0:
                detail_filename = sanitize_url_for_filename(url)
                suspicious_summary_data.append((url, suspicious_configs_count_for_url, detail_filename))
                detail_filepath = os.path.join(OUTPUT_DETAILS_DIR, detail_filename)
                try:
                    with open(detail_filepath, 'w', encoding='utf-8') as f_detail:
                        f_detail.write(f"جزئیات کانفیگ‌های مشکوک برای URL:\n{url}\n")
                        f_detail.write("======================================================================\n\n")
                        for detail_entry in current_url_suspicious_config_details_for_file:
                            f_detail.write(detail_entry)
                    print(f"  گزارش جزئیات مشکوک برای {url} در فایل {detail_filepath} ذخیره شد.")
                except Exception as e:
                    print(f"  خطا در نوشتن فایل جزئیات مشکوک {detail_filepath}: {e}")
        print("-" * 30)

    # ذخیره پایگاه داده وضعیت به‌روز شده
    save_status_db(status_db)

    # --- نوشتن فایل گزارش خلاصه کانفیگ‌های مشکوک (بدون تغییر) ---
    try:
        with open(main_summary_report_file_path, 'w', encoding='utf-8') as f_main_report:
            if not suspicious_summary_data:
                f_main_report.write("هیچ کانفیگ مشکوکی در URLهای پردازش شده یافت نشد.\n")
            else:
                f_main_report.write("خلاصه URLهایی که دارای کانفیگ‌های مشکوک بودند:\n")
                f_main_report.write("================================================\n\n")
                for u, count, detail_file in suspicious_summary_data:
                    f_main_report.write(f"URL: {u}\n")
                    f_main_report.write(f"  تعداد کانفیگ‌های مشکوک: {count}\n")
                    f_main_report.write(f"  فایل جزئیات: ./{OUTPUT_DETAILS_DIR}/{detail_file}\n")
                    f_main_report.write("------------------------------------------------\n")
            print(f"\nفایل گزارش خلاصه کانفیگ‌های مشکوک ایجاد شد: {main_summary_report_file_path}")
    except Exception as e:
        print(f"خطا در نوشتن فایل گزارش خلاصه '{main_summary_report_file_path}': {e}")

    # مرتب‌سازی داده‌های گزارش قدمت لینک‌ها
    # لینک‌های جدیدتر و به‌روزتر در بالا، قدیمی‌ترها و خطاها در پایین
    staleness_data_for_sorting.sort(key=lambda x: x["sort_key"])

    # نوشتن فایل گزارش قدمت لینک‌ها (مرتب شده)
    try:
        with open(STALENESS_REPORT_FILE, 'w', encoding='utf-8') as f_staleness_report:
            f_staleness_report.write("گزارش وضعیت به‌روزرسانی لینک‌ها\n")
            f_staleness_report.write("==============================\n")
            f_staleness_report.write(f"گزارش تولید شده در: {current_run_time_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            if not staleness_data_for_sorting:
                f_staleness_report.write("هیچ لینکی برای بررسی وضعیت به‌روزرسانی پردازش نشد.\n")
            else:
                for entry in staleness_data_for_sorting:
                    f_staleness_report.write(f"URL: {entry['url']}\n")
                    f_staleness_report.write(f"وضعیت: {entry['message']}\n\n")
            print(f"فایل گزارش قدمت لینک‌ها (مرتب شده) ایجاد شد: {STALENESS_REPORT_FILE}")
    except Exception as e:
        print(f"خطا در نوشتن فایل گزارش قدمت لینک‌ها ({STALENESS_REPORT_FILE}): {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("نحوه استفاده: python filter_configs.py <مسیر_فایل_لینک‌ها> <مسیر_فایل_گزارش_اصلی_مشکوک‌ها>")
        sys.exit(1)
    
    links_file_arg = sys.argv[1]
    main_summary_report_file_arg = sys.argv[2]
    main(links_file_arg, main_summary_report_file_arg)
