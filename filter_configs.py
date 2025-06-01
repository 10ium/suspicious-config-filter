import requests
import base64
import os
import re
import sys

# --- ثابت‌های پیکربندی ---
# مقادیر از متغیرهای محیطی که توسط اکشن گیت‌هاب تنظیم می‌شوند، خوانده خواهند شد
# مقادیر پیش‌فرض در صورتی که اسکریپت خارج از اکشن اجرا شود، در اینجا ارائه شده‌اند
MIN_PERCENT25_COUNT = int(os.environ.get('MIN_PERCENT25_COUNT', 15))
MAX_CONFIG_LENGTH = int(os.environ.get('MAX_CONFIG_LENGTH', 1500))
KEYWORD = "i_love_"  # کلمه کلیدی برای جستجو (بدون حساسیت به حروف)
DOUBLE_ENCODING_SEQUENCE = "%2525"  # دنباله کدگذاری دوگانه
CONFIG_PREFIXES = (  # پیشوندهای معتبر برای شناسایی انواع کانفیگ‌ها
    "vmess://", "vless://", "trojan://",
    "ss://", "ssr://", "tuic://", "hy2://"
)
REQUEST_TIMEOUT = 20 # زمان وقفه برای درخواست‌های HTTP (به ثانیه)

def add_base64_padding(s: str) -> str:
    """پدینگ لازم را به یک رشته Base64 اضافه می‌کند."""
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return s

def decode_subscription_content(content_bytes: bytes) -> tuple[str, bool]:
    """
    محتوای اشتراک (subscription) را دیکود می‌کند.
    - اگر content_bytes، پس از دیکود شدن به UTF-8، یک رشته Base64 معتبر تشکیل دهد
      که سپس به یک رشته چند خطی یا حاوی پیشوندهای کانفیگ دیکود شود، آن رشته دیکود شده را برمی‌گرداند.
    - در غیر این صورت، محتوای content_bytes که به UTF-8 دیکود شده را همانطور که هست برمی‌گرداند.
    محتوای متنی پردازش شده و یک پرچم بولی که نشان می‌دهد آیا دیکود Base64 (از یک رشته پی‌لود) رخ داده است یا خیر، برگردانده می‌شود.
    """
    text_content_from_bytes = ""
    was_base64_decoded = False

    try:
        # ابتدا سعی کنید کل محتوای بایت را به عنوان یک رشته UTF-8 دیکود کنید.
        # این رشته ممکن است *خودش* پی‌لود Base64 باشد.
        text_payload_candidate = content_bytes.decode('utf-8')
        
        # رشته کاندید را پاکسازی کنید: تمام فاصله‌های خالی را حذف و سپس پدینگ اضافه کنید.
        cleaned_b64_string = "".join(text_payload_candidate.split()) # حذف تمام فاصله‌های خالی
        
        # بررسی کنید که آیا این رشته پاکسازی شده خالی نیست و به نظر Base64 می‌آید
        if cleaned_b64_string and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", cleaned_b64_string): # بررسی دقیق‌تر کاراکترهای Base64
            padded_b64_string = add_base64_padding(cleaned_b64_string) # اطمینان از وجود پدینگ
            try:
                decoded_bytes_from_string = base64.b64decode(padded_b64_string)
                final_text_content_check = decoded_bytes_from_string.decode('utf-8')
                
                # روش اکتشافی: اگر محتوای دیکود شده دارای خطوط جدید یا پیشوندهای شناخته شده باشد، احتمالاً یک پی‌لود Base64 بوده است
                if '\n' in final_text_content_check or any(prefix in final_text_content_check for prefix in CONFIG_PREFIXES):
                    text_content_from_bytes = final_text_content_check
                    was_base64_decoded = True
                    # print(f"محتوا یک پی‌لود رشته‌ای کدگذاری شده با Base64 بود و با موفقیت دیکود شد.") # برای دیباگ
                else:
                    # به خوبی دیکود شد، اما شبیه لیست کانفیگ‌ها نیست.
                    # text_payload_candidate اصلی را به عنوان متن ساده در نظر بگیرید.
                    # print(f"محتوا از Base64 دیکود شد، اما به عنوان لیست کانفیگ شناسایی نشد. از متن اصلی استفاده می‌شود.") # برای دیباگ
                    text_content_from_bytes = text_payload_candidate
            except (base64.binascii.Error, UnicodeDecodeError):
                # دیکود Base64 رشته ناموفق بود، بنابراین احتمالاً متن ساده است.
                # print(f"محتوای رشته Base64 نیست یا در دیکود ناموفق بود. به عنوان متن ساده در نظر گرفته می‌شود.") # برای دیباگ
                text_content_from_bytes = text_payload_candidate
        else:
            # رشته شبیه Base64 نیست، آن را متن ساده در نظر بگیرید.
            # print(f"محتوای رشته به نظر Base64 نمی‌آید. به عنوان متن ساده در نظر گرفته می‌شود.") # برای دیباگ
            text_content_from_bytes = text_payload_candidate

    except UnicodeDecodeError:
        # اگر content_bytes نتواند به عنوان UTF-8 دیکود شود، بعید است که یک پی‌لود Base64 متنی باشد.
        # ممکن است داده‌های باینری خام باشد که اتفاقاً Base64 هستند، اما این برای اشتراک‌ها کمتر رایج است.
        # برای اطمینان، دیکود مستقیم Base64 بایت‌های خام را امتحان کنید.
        # print(f"content_bytes UTF-8 معتبر نیست. تلاش برای دیکود مستقیم Base64 بایت‌های خام.") # برای دیباگ
        try:
            temp_str_for_padding = content_bytes.decode('ascii', errors='ignore').strip()
            padded_b64_bytes_direct = add_base64_padding(temp_str_for_padding).encode('ascii')
            decoded_bytes_direct = base64.b64decode(padded_b64_bytes_direct)
            text_content_from_bytes = decoded_bytes_direct.decode('utf-8')
            was_base64_decoded = True
            # print(f"بایت‌های خام با موفقیت به عنوان Base64 دیکود شدند.") # برای دیباگ
        except Exception: 
            # print(f"دیکود مستقیم Base64 بایت‌های خام ناموفق بود. استفاده از UTF-8 با نادیده گرفتن خطاها.") # برای دیباگ
            text_content_from_bytes = content_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        # print(f"خطای عمومی در decode_subscription_content: {e}. استفاده از UTF-8 با نادیده گرفتن خطاها.") # برای دیباگ
        text_content_from_bytes = content_bytes.decode('utf-8', errors='ignore')
        
    return text_content_from_bytes, was_base64_decoded

def check_config_suspicious(config_str: str) -> list[str]:
    """یک رشته کانفیگ تکی را بر اساس معیارهای تعریف شده بررسی می‌کند."""
    reasons = []
    # ۱. حاوی کلمه کلیدی خاص (بدون حساسیت به بزرگی و کوچکی حروف)
    if KEYWORD.lower() in config_str.lower():
        reasons.append(f"حاوی کلمه کلیدی '{KEYWORD}' است")

    # ۲. کدگذاری URL سنگین
    percent25_count = config_str.count("%25")
    if percent25_count >= MIN_PERCENT25_COUNT:
        reasons.append(f"تعداد '%25' ({percent25_count}) برابر یا بیشتر از {MIN_PERCENT25_COUNT} است")

    # ۳. طول بیش از حد
    config_len = len(config_str)
    if config_len >= MAX_CONFIG_LENGTH:
        reasons.append(f"طول ({config_len}) برابر یا بیشتر از {MAX_CONFIG_LENGTH} است")

    # ۴. حاوی دنباله کدگذاری دوگانه خاص
    if DOUBLE_ENCODING_SEQUENCE in config_str:
        reasons.append(f"حاوی دنباله کدگذاری دوگانه '{DOUBLE_ENCODING_SEQUENCE}' است")
    
    return reasons

def main(links_file_path: str, report_file_path: str):
    """
    تابع اصلی برای پردازش URL‌ها، فیلتر کردن کانفیگ‌ها و ایجاد گزارش.
    """
    report_lines = []
    
    try:
        with open(links_file_path, 'r', encoding='utf-8') as f_links:
            # خواندن URLها، حذف فضاهای خالی و نادیده گرفتن خطوطی که با # شروع می‌شوند (برای کامنت)
            urls = [line.strip() for line in f_links if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"خطا: فایل لینک‌ها در مسیر '{links_file_path}' یافت نشد.")
        sys.exit(1)
    except Exception as e:
        print(f"خطا در خواندن فایل لینک‌ها '{links_file_path}': {e}")
        sys.exit(1)

    for url in urls:
        report_lines.append(f"URL: {url}")
        print(f"درحال پردازش URL: {url}")
        
        suspicious_configs_count_for_url = 0
        current_url_suspicious_details = []
        # استفاده از یک مجموعه (set) برای ذخیره رشته‌های کانفیگ مشکوک منحصر به فرد برای گزارش‌دهی دقیق ذیل این URL
        unique_flagged_configs_for_this_url = set()

        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status() # ایجاد استثنا برای پاسخ‌های ناموفق (4XX یا 5XX)
            content_bytes = response.content
        except requests.exceptions.Timeout:
            error_message = f"  خطا: وقفه زمانی (Timeout) هنگام دریافت URL ({REQUEST_TIMEOUT} ثانیه)"
            print(error_message)
            report_lines.append(error_message)
        except requests.exceptions.RequestException as e:
            error_message = f"  خطا در دریافت URL: {e}"
            print(error_message)
            report_lines.append(error_message)
        else: # اگر در طول درخواست استثنایی رخ ندهد
            text_content, was_decoded = decode_subscription_content(content_bytes)
            if was_decoded:
                print(f"  محتوای {url} با Base64 دیکود شد.")
            
            config_lines = text_content.splitlines()
            print(f"  تعداد {len(config_lines)} خط برای پردازش از {url} یافت شد.")

            for i, line_content in enumerate(config_lines):
                config_str = line_content.strip()
                if not config_str: # رد شدن از خطوط خالی
                    continue

                # بررسی اینکه آیا یک نوع کانفیگ شناخته شده بر اساس پیشوند است
                if not any(config_str.startswith(prefix) for prefix in CONFIG_PREFIXES):
                    # print(f"  خط {i+1} رد شد (نوع کانفیگ شناخته شده نیست): {config_str[:70]}...") # برای دیباگ
                    continue
                
                reasons = check_config_suspicious(config_str)
                if reasons:
                    suspicious_configs_count_for_url += 1
                    # اضافه کردن به گزارش دقیق فقط اگر این رشته کانفیگ خاص هنوز برای این URL ثبت نشده باشد
                    if config_str not in unique_flagged_configs_for_this_url:
                        detail = f"کانفیگ: {config_str}\nدلایل:\n"
                        for reason in reasons:
                            detail += f"  - {reason}\n"
                        current_url_suspicious_details.append(detail)
                        unique_flagged_configs_for_this_url.add(config_str)
                    # print(f"  کانفیگ مشکوک علامت‌گذاری شد: {config_str[:70]}... دلایل: {reasons}") # برای دیباگ

        report_lines.append(f"تعداد کانفیگ‌های مشکوک یافت شده: {suspicious_configs_count_for_url}")
        report_lines.append("---------------------------------------")
        report_lines.extend(current_url_suspicious_details)
        report_lines.append("=======================================\n")
        print(f"  پردازش URL به پایان رسید. تعداد {suspicious_configs_count_for_url} کانفیگ مشکوک یافت شد.")

    try:
        with open(report_file_path, 'w', encoding='utf-8') as f_report:
            f_report.write("\n".join(report_lines))
        print(f"\nگزارش ایجاد شد: {report_file_path}")
    except Exception as e:
        print(f"خطا در نوشتن فایل گزارش '{report_file_path}': {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("نحوه استفاده: python filter_configs.py <مسیر_فایل_لینک‌ها> <مسیر_فایل_گزارش>")
        sys.exit(1)
    
    links_file = sys.argv[1]
    report_file = sys.argv[2]
    main(links_file, report_file)
