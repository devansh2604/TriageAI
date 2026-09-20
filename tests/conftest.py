import pytest
from src.data.parse import make_alert

@pytest.fixture
def alert():
    return make_alert(subject="Urgent account suspended", body_text="Dear customer, verify your account immediately.",
                      body_html='<a href="http://paypal-login.example">https://paypal.com</a>',
                      from_addr="PayPal <x@evil.example>", reply_to="other@evil.example", label=1)
