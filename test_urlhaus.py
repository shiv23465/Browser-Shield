from modules.urlhaus_client import check_urlhaus

url = input("Enter URL to check: ").strip()

result = check_urlhaus(url)

print("\nBrowser Shield - URLhaus Result")
print("--------------------------------")
for key, value in result.items():
    print(f"{key}: {value}")