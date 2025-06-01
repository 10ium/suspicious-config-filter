import requests
import base64
import os
import re
import sys
import hashlib # برای ایجاد نام فایل‌های یکتا و کوتاه از URLها

# --- ثابت‌های پیکربندی ---
MIN_PERCENT25_COUNT = int(os.environ.get('MIN_PERCENT25_COUNT', 15))
MAX_CONFIG_LENGTH = int(os.environ.get('MAX_CONFIG_LENGTH', 1500))
KEYWORD = "i_love_"
DOUBLE_ENCODING_SEQUENCE = "%2525"
CONFIG_PREFIXES = (
    "vmess://", "vless://", "trojan://",
    "ss://", "ssr://", "tuic://", "hy2://"
)
REQUEST_TIMEOUT = 20
OUTPUT_DETAILS_DIR = "suspicious_config_details" # نام پوشه برای گزارش‌های جزئی

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
    """یک نام فایل امن و کوتاه از URL ایجاد می‌کند."""
    # استفاده از هش برای جلوگیری از نام‌های طولانی یا کاراکترهای نامعتبر
    # و همچنین برای یکتاسازی نسبی در صورت شباهت بخش اولیه URLها
    url_hash = hashlib.md5(url_str.encode('utf-8')).hexdigest()[:8] # یک هش کوتاه
    
    # تلاش برای گرفتن بخشی از نام دامنه برای خوانایی
    try:
        domain_part = re.match(r"https?://([^/]+)", url_str).group(1)
        # جایگزینی کاراکترهای نامعتبر در بخش دامنه
        safe_domain_part = re.sub(r'[^\w.-]', '_', domain_part)
        filename_base = f"{safe_domain_part}_{url_hash}"
    except AttributeError: # اگر URL فرمت مورد انتظار را نداشت
        filename_base = f"url_{url_hash}"
        
    return filename_base + ".txt"


def main(links_file_path: str, main_report_file_path: str):
    urls_with_suspicious_configs_summary = [] # (url, count, detail_file_name)

    # ایجاد پوشه برای گزارش‌های جزئی اگر وجود ندارد
    os.makedirs(OUTPUT_DETAILS_DIR, exist_ok=True)
    print(f"پوشه گزارش‌های جزئی: {os.path.abspath(OUTPUT_DETAILS_DIR)}")

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
        current_url_suspicious_config_details_for_file = [] # جزئیات برای فایل اختصاصی این URL
        suspicious_configs_count_for_url = 0
        
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            content_bytes = response.content
        except requests.exceptions.RequestException as e:
            print(f"  خطا در دریافت URL {url}: {e}")
            # اگر URL خطا داشت، در گزارش اصلی نمی‌آید مگر اینکه بخواهید خطاها را هم گزارش کنید
            continue # رفتن به URL بعدی

        text_content, _ = decode_subscription_content(content_bytes)
        config_lines = text_content.splitlines()
        
        unique_flagged_configs_in_this_url = set() # برای جلوگیری از ثبت مکرر یک کانفیگ در فایل جزئیات

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
            urls_with_suspicious_configs_summary.append((url, suspicious_configs_count_for_url, detail_filename))
            
            detail_filepath = os.path.join(OUTPUT_DETAILS_DIR, detail_filename)
            try:
                with open(detail_filepath, 'w', encoding='utf-8') as f_detail:
                    f_detail.write(f"جزئیات کانفیگ‌های مشکوک برای URL:\n{url}\n")
                    f_detail.write("======================================================================\n\n")
                    for detail_entry in current_url_suspicious_config_details_for_file:
                        f_detail.write(detail_entry)
                print(f"  گزارش جزئیات برای {url} در فایل {detail_filepath} ذخیره شد. تعداد: {suspicious_configs_count_for_url}")
            except Exception as e:
                print(f"  خطا در نوشتن فایل جزئیات {detail_filepath}: {e}")
        else:
            print(f"  هیچ کانفیگ مشکوکی برای URL {url} یافت نشد.")


    # نوشتن فایل گزارش اصلی (خلاصه)
    try:
        with open(main_report_file_path, 'w', encoding='utf-8') as f_main_report:
            if not urls_with_suspicious_configs_summary:
                f_main_report.write("هیچ کانفیگ مشکوکی در URLهای پردازش شده یافت نشد.\n")
                print("\nفایل گزارش اصلی: هیچ کانفیگ مشکوکی یافت نشد.")
            else:
                f_main_report.write("خلاصه URLهایی که دارای کانفیگ‌های مشکوک بودند:\n")
                f_main_report.write("================================================\n\n")
                for u, count, detail_file in urls_with_suspicious_configs_summary:
                    f_main_report.write(f"URL: {u}\n")
                    f_main_report.write(f"  تعداد کانفیگ‌های مشکوک: {count}\n")
                    f_main_report.write(f"  فایل جزئیات: ./{OUTPUT_DETAILS_DIR}/{detail_file}\n")
                    f_main_report.write("------------------------------------------------\n")
                print(f"\nفایل گزارش اصلی ایجاد شد: {main_report_file_path}")
    except Exception as e:
        print(f"خطا در نوشتن فایل گزارش اصلی '{main_report_file_path}': {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("نحوه استفاده: python filter_configs.py <مسیر_فایل_لینک‌ها> <مسیر_فایل_گزارش_اصلی>")
        sys.exit(1)
    
    links_file_arg = sys.argv[1]
    main_report_file_arg = sys.argv[2]
    main(links_file_arg, main_report_file_arg)
