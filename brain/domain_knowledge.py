"""Domain Knowledge Pack for Project Triage v4.

Provides domain-specific vulnerability patterns and business logic attack
templates for: fintech, e-commerce, healthcare, automotive, social/messaging,
and SaaS/B2B.

Research basis: OWASP Top 10 for Business Logic Abuse (BLA1-BLA10, May 2025).
None of the current autonomous pentest agents incorporate domain context -
they all treat targets as generic URLs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DomainPattern:
    """A domain-specific vulnerability pattern with testing methodology."""

    domain: str          # fintech, ecommerce, healthcare, automotive, social, saas
    category: str        # BLA category: BLA1-BLA10 or custom
    name: str            # e.g. "double_spend_race"
    description: str     # what the vulnerability is
    detection_signals: list[str]   # what to look for in the application
    test_methodology: list[str]    # step-by-step how to test
    impact: str          # why this matters
    severity: str        # critical/high/medium
    bounty_range: str    # e.g. "$5K-$50K"


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

_FINTECH_PATTERNS: list[DomainPattern] = [
    DomainPattern(
        domain="fintech",
        category="BLA2",
        name="double_spend_race",
        description="Concurrent balance deductions via race condition allow spending the same funds twice. "
                    "Send parallel transfer/withdrawal requests to exploit non-atomic balance checks.",
        detection_signals=[
            "/transfer", "/withdraw", "/send", "/payment",
            "balance", "amount", "idempotency", "X-Idempotency-Key",
        ],
        test_methodology=[
            "1. Authenticate and note current balance",
            "2. Craft a transfer/withdrawal request for the full balance",
            "3. Send 10-50 identical requests concurrently (asyncio / threading)",
            "4. Check if total debited exceeds original balance",
            "5. Verify with GET /balance or transaction history",
        ],
        impact="Direct financial loss - attacker drains more funds than they hold",
        severity="critical",
        bounty_range="$5K-$50K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA3",
        name="negative_balance_exploit",
        description="Submitting negative quantities or amounts causes the system to credit rather "
                    "than debit, effectively generating money from nothing.",
        detection_signals=[
            "amount", "quantity", "value", "/transfer", "/payment",
            "numeric input field", "currency amount",
        ],
        test_methodology=[
            "1. Intercept a payment or transfer request",
            "2. Change the amount field to a negative value (e.g. -100)",
            "3. Submit and observe whether balance increases",
            "4. Try negative quantities on invoice line items",
            "5. Test boundary: -0.01, -1, -999999",
        ],
        impact="Unlimited fund generation via sign confusion",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA4",
        name="fee_manipulation",
        description="Concurrent application of discounts/fee waivers via race condition results "
                    "in double fee reduction or zero-fee transactions.",
        detection_signals=[
            "/fee", "/discount", "/promo", "/waive", "fee_amount",
            "discount_code", "promo_code",
        ],
        test_methodology=[
            "1. Identify a fee or discount application endpoint",
            "2. Send concurrent requests applying the same discount",
            "3. Check if fees are reduced multiple times",
            "4. Try applying multiple different promo codes simultaneously",
            "5. Verify final transaction amount vs expected",
        ],
        impact="Revenue loss from bypassed fees and stacked discounts",
        severity="high",
        bounty_range="$2K-$15K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA5",
        name="currency_confusion",
        description="Pay in a low-value currency but get credited in a high-value currency. "
                    "Exploit mismatches between currency fields in request vs server-side processing.",
        detection_signals=[
            "currency", "currency_code", "ISO 4217", "USD", "EUR", "JPY",
            "/convert", "/exchange", "fx_rate",
        ],
        test_methodology=[
            "1. Initiate a payment specifying currency A (e.g. JPY)",
            "2. Modify the currency field in the request body to currency B (e.g. USD)",
            "3. Check if 100 JPY payment is credited as 100 USD",
            "4. Test on deposit, withdrawal, and transfer endpoints separately",
            "5. Check for client-side vs server-side currency validation",
        ],
        impact="Massive arbitrage - 1 JPY treated as 1 USD is ~150x gain",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA6",
        name="interest_calculation_bypass",
        description="Manipulate dates, timestamps, or loan terms to avoid interest accrual or "
                    "trigger incorrect interest calculations.",
        detection_signals=[
            "interest", "accrual", "loan", "due_date", "payment_date",
            "/loan", "/interest", "apr", "rate",
        ],
        test_methodology=[
            "1. Identify loan or interest-bearing account endpoints",
            "2. Modify date parameters (due_date, payment_date) in requests",
            "3. Set repayment date to same as disbursement date",
            "4. Check if interest is calculated as zero",
            "5. Test timezone manipulation to shift effective dates",
        ],
        impact="Interest-free borrowing, loss of lender revenue",
        severity="high",
        bounty_range="$3K-$20K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA2",
        name="transfer_atomicity_violation",
        description="Debit succeeds but credit fails (or vice versa) when the transfer is not "
                    "wrapped in a transaction. Funds vanish or are duplicated.",
        detection_signals=[
            "/transfer", "/send", "from_account", "to_account",
            "debit", "credit", "transaction",
        ],
        test_methodology=[
            "1. Initiate a transfer between two accounts",
            "2. Cause the credit side to fail (invalid recipient, trigger error)",
            "3. Check if debit still went through on sender's account",
            "4. Test with network interruption mid-transfer",
            "5. Check for rollback or compensation transactions",
        ],
        impact="Funds lost in transit or duplicated across accounts",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA7",
        name="account_linking_abuse",
        description="Link an attacker-controlled account to a victim's bank or payment method "
                    "by manipulating account linking flows.",
        detection_signals=[
            "/link", "/connect", "/plaid", "/bank", "account_id",
            "routing_number", "institution_id",
        ],
        test_methodology=[
            "1. Start account linking flow for your own account",
            "2. Intercept the callback/webhook and swap account identifiers",
            "3. Replace your bank account ID with victim's",
            "4. Complete the linking flow",
            "5. Verify if victim's bank is now linked to attacker's app account",
        ],
        impact="Full access to victim's linked bank account via the application",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA8",
        name="chargeback_fraud_via_api",
        description="Trigger a refund through the API while retaining the purchased goods or "
                    "transferred funds. Exploit refund/chargeback logic that doesn't verify delivery.",
        detection_signals=[
            "/refund", "/chargeback", "/dispute", "/return",
            "order_id", "transaction_id", "refund_amount",
        ],
        test_methodology=[
            "1. Complete a legitimate purchase or transfer",
            "2. Immediately request a refund via API",
            "3. Check if goods/funds are retained while refund processes",
            "4. Test partial refund for more than the item cost",
            "5. Race the refund against the fulfillment process",
        ],
        impact="Double-dip: keep goods and get money back",
        severity="high",
        bounty_range="$3K-$20K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA9",
        name="rounding_error_accumulation",
        description="Exploit floating-point rounding in financial calculations. Repeatedly perform "
                    "micro-transactions where rounding always favors the attacker.",
        detection_signals=[
            "amount", "balance", "decimal", "precision",
            "/transfer", "/convert", "float", "double",
        ],
        test_methodology=[
            "1. Identify endpoints handling currency calculations",
            "2. Send transactions with amounts that trigger rounding (e.g. $0.001)",
            "3. Perform many small transactions and track cumulative balance",
            "4. Check if rounding consistently favors one direction",
            "5. Test currency conversion with irrational exchange rates",
        ],
        impact="Slow fund siphoning via salami attack - small per-tx but scales",
        severity="medium",
        bounty_range="$1K-$10K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA10",
        name="wire_transfer_replay",
        description="Replay a signed or authorized wire transfer request to execute the transfer "
                    "multiple times. Exploit missing replay protection.",
        detection_signals=[
            "/wire", "/transfer", "signature", "nonce", "timestamp",
            "X-Request-ID", "idempotency",
        ],
        test_methodology=[
            "1. Capture a successful wire transfer request (headers + body)",
            "2. Replay the exact same request",
            "3. Check if the transfer executes again",
            "4. Test with slight timestamp modifications",
            "5. Verify idempotency key enforcement",
        ],
        impact="Unlimited fund transfers from a single authorization",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="fintech",
        category="BLA3",
        name="limit_bypass_via_parameter_pollution",
        description="Bypass transaction limits by sending duplicate or conflicting limit parameters "
                    "that confuse server-side validation.",
        detection_signals=[
            "limit", "max_amount", "daily_limit", "transaction_limit",
            "/settings", "/limits",
        ],
        test_methodology=[
            "1. Identify transaction limit enforcement endpoints",
            "2. Send request with duplicate amount parameters",
            "3. Try HTTP parameter pollution (amount=100&amount=999999)",
            "4. Test JSON key duplication in request body",
            "5. Check if limit is validated client-side only",
        ],
        impact="Bypass withdrawal/transfer limits for unauthorized large transactions",
        severity="high",
        bounty_range="$3K-$20K",
    ),
]

_ECOMMERCE_PATTERNS: list[DomainPattern] = [
    DomainPattern(
        domain="ecommerce",
        category="BLA1",
        name="price_manipulation",
        description="Modify the price field in the checkout POST body to pay less than the listed price. "
                    "Server trusts client-supplied price without validation.",
        detection_signals=[
            "/checkout", "/order", "/cart", "price", "total",
            "unit_price", "subtotal", "amount",
        ],
        test_methodology=[
            "1. Add an item to cart and proceed to checkout",
            "2. Intercept the checkout/order POST request",
            "3. Modify price/total/unit_price to $0.01",
            "4. Submit and check if order succeeds at modified price",
            "5. Test modifying individual line item prices vs total",
        ],
        impact="Purchase goods for arbitrary low price",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA3",
        name="negative_quantity_refund",
        description="Order negative quantities of items to receive a credit on the account "
                    "instead of a charge.",
        detection_signals=[
            "quantity", "qty", "count", "/cart/add", "/order",
            "line_items", "item_count",
        ],
        test_methodology=[
            "1. Add an item to cart",
            "2. Intercept the request and change quantity to -1",
            "3. Proceed to checkout and check total (should be negative)",
            "4. Complete the order and verify if account is credited",
            "5. Test with mixed positive and negative quantities",
        ],
        impact="Generate store credit or refunds from thin air",
        severity="critical",
        bounty_range="$3K-$20K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA2",
        name="coupon_stacking_race",
        description="Apply multiple mutually exclusive coupons via concurrent requests. "
                    "Race condition bypasses the 'one coupon per order' check.",
        detection_signals=[
            "/coupon", "/promo", "/discount", "coupon_code",
            "discount_code", "promo_code", "/apply",
        ],
        test_methodology=[
            "1. Obtain multiple coupon/promo codes",
            "2. Create a cart and proceed to pre-checkout state",
            "3. Send concurrent requests applying different coupons",
            "4. Check if multiple discounts are applied to the same order",
            "5. Verify final price reflects stacked discounts",
        ],
        impact="Massive discounts via stacking - potentially free goods",
        severity="high",
        bounty_range="$2K-$15K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA2",
        name="inventory_race_condition",
        description="Oversell limited-stock items by sending concurrent purchase requests "
                    "that all pass the stock check before any decrement.",
        detection_signals=[
            "stock", "inventory", "quantity", "available",
            "limited", "/purchase", "/buy",
        ],
        test_methodology=[
            "1. Find a product with limited stock (e.g. 1 remaining)",
            "2. Send 10+ concurrent purchase requests",
            "3. Check how many orders succeed",
            "4. Verify if inventory goes negative",
            "5. Test with flash sale or limited-edition items",
        ],
        impact="Overselling inventory, fulfillment chaos, financial loss",
        severity="high",
        bounty_range="$2K-$10K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA2",
        name="gift_card_balance_duplication",
        description="Redeem the same gift card concurrently across multiple sessions to "
                    "drain it multiple times before the balance updates.",
        detection_signals=[
            "/gift-card", "/giftcard", "/redeem", "card_number",
            "pin", "balance", "gift_card_id",
        ],
        test_methodology=[
            "1. Obtain a gift card with known balance",
            "2. Create multiple sessions/carts simultaneously",
            "3. Apply the gift card to all carts concurrently",
            "4. Complete all checkouts simultaneously",
            "5. Verify total redeemed exceeds original card balance",
        ],
        impact="Gift card balance multiplied - direct financial loss",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA4",
        name="free_shipping_threshold_manipulation",
        description="Add items to exceed the free shipping threshold, then remove them after "
                    "free shipping is locked in.",
        detection_signals=[
            "/cart", "/shipping", "shipping_method", "free_shipping",
            "threshold", "subtotal", "/cart/remove",
        ],
        test_methodology=[
            "1. Check free shipping threshold (e.g. orders over $50)",
            "2. Add items totaling above threshold",
            "3. Proceed past shipping selection (free shipping applied)",
            "4. Remove items to bring total below threshold",
            "5. Complete checkout - check if free shipping persists",
        ],
        impact="Free shipping on all orders regardless of value",
        severity="medium",
        bounty_range="$500-$3K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA5",
        name="order_modification_after_payment",
        description="Change order contents (upgrade items, increase quantity) after payment "
                    "has been captured but before fulfillment.",
        detection_signals=[
            "/order/modify", "/order/update", "/order/edit",
            "order_id", "line_items", "status",
        ],
        test_methodology=[
            "1. Place and pay for a small order",
            "2. Find the order modification endpoint",
            "3. Change line items to more expensive products",
            "4. Increase quantities",
            "5. Check if modifications are accepted without additional payment",
        ],
        impact="Receive more or better goods than paid for",
        severity="high",
        bounty_range="$3K-$15K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA6",
        name="referral_abuse",
        description="Self-refer via multiple accounts or manipulate referral tracking to "
                    "earn referral bonuses fraudulently.",
        detection_signals=[
            "/referral", "/invite", "/refer", "referral_code",
            "invite_code", "referrer_id", "bonus",
        ],
        test_methodology=[
            "1. Get your referral code/link",
            "2. Create a new account using the referral",
            "3. Check if referral bonus is credited",
            "4. Test if same email with + aliasing works",
            "5. Test if referral code can be applied post-registration",
        ],
        impact="Unlimited referral bonuses via fake accounts",
        severity="medium",
        bounty_range="$1K-$5K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA2",
        name="flash_sale_bypass",
        description="Pre-cache or pre-build the add-to-cart request before a flash sale starts, "
                    "bypassing queue or timing controls.",
        detection_signals=[
            "flash", "sale", "limited", "countdown", "queue",
            "/add-to-cart", "sale_id", "start_time",
        ],
        test_methodology=[
            "1. Inspect the add-to-cart request for a regular product",
            "2. Identify the flash sale product ID before sale starts",
            "3. Pre-craft the add-to-cart request with correct parameters",
            "4. Send at or before sale start time",
            "5. Check if purchase succeeds before public sale opens",
        ],
        impact="Unfair advantage, buy out limited stock before legitimate buyers",
        severity="medium",
        bounty_range="$1K-$5K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA7",
        name="subscription_downgrade_feature_retention",
        description="Downgrade subscription tier but retain access to premium features "
                    "due to missing entitlement revocation.",
        detection_signals=[
            "/subscription", "/plan", "/downgrade", "/upgrade",
            "tier", "plan_id", "features", "entitlements",
        ],
        test_methodology=[
            "1. Subscribe to premium/highest tier",
            "2. Verify access to all premium features",
            "3. Downgrade to free/basic tier",
            "4. Check if premium features are still accessible",
            "5. Test specific feature endpoints with downgraded session",
        ],
        impact="Premium features at free-tier cost",
        severity="high",
        bounty_range="$2K-$10K",
    ),
    DomainPattern(
        domain="ecommerce",
        category="BLA1",
        name="tax_exemption_abuse",
        description="Manipulate tax calculation by injecting tax-exempt flags or modifying "
                    "shipping address to tax-free jurisdictions mid-checkout.",
        detection_signals=[
            "tax", "tax_exempt", "tax_id", "vat", "gst",
            "/tax", "shipping_address", "billing_address",
        ],
        test_methodology=[
            "1. Intercept checkout request",
            "2. Add tax_exempt=true or tax_rate=0 to the request",
            "3. Modify shipping address to a tax-free jurisdiction",
            "4. Change address back after tax calculation but before payment",
            "5. Check final charged amount for tax inclusion",
        ],
        impact="Tax evasion on all purchases",
        severity="medium",
        bounty_range="$1K-$5K",
    ),
]

_HEALTHCARE_PATTERNS: list[DomainPattern] = [
    DomainPattern(
        domain="healthcare",
        category="BLA1",
        name="patient_record_idor",
        description="Sequential or predictable patient IDs allow accessing any patient's "
                    "medical records by enumerating the ID parameter.",
        detection_signals=[
            "/patient", "/record", "/medical", "patient_id",
            "record_id", "mrn", "medical_record_number",
        ],
        test_methodology=[
            "1. Access your own patient record and note the ID",
            "2. Increment/decrement the patient_id parameter",
            "3. Check if another patient's record is returned",
            "4. Test with UUID if IDs aren't sequential (try common UUIDs)",
            "5. Check API responses for data leakage in error messages",
        ],
        impact="Mass exposure of protected health information (PHI) - HIPAA violation",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA1",
        name="prescription_data_idor",
        description="Access any patient's prescription data by manipulating prescription "
                    "endpoint IDs. Often uses sequential numeric identifiers.",
        detection_signals=[
            "/prescription", "/rx", "/medication", "prescription_id",
            "rx_number", "medication_id",
        ],
        test_methodology=[
            "1. Access your own prescription endpoint",
            "2. Note the prescription ID format",
            "3. Enumerate other prescription IDs",
            "4. Check if prescription details are returned for other patients",
            "5. Test both GET and POST endpoints for prescription data",
        ],
        impact="Exposure of prescription history - reveals conditions, controlled substances",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA4",
        name="appointment_manipulation",
        description="Book, cancel, or modify other patients' appointments by manipulating "
                    "appointment IDs or patient references.",
        detection_signals=[
            "/appointment", "/schedule", "/booking", "appointment_id",
            "slot_id", "provider_id", "patient_id",
        ],
        test_methodology=[
            "1. Book an appointment as yourself",
            "2. Intercept the booking request and change patient_id",
            "3. Try canceling appointments with different appointment_ids",
            "4. Modify appointment details for other patients",
            "5. Check if double-booking is possible on same slot",
        ],
        impact="Denial of care via canceled appointments, privacy breach",
        severity="high",
        bounty_range="$2K-$15K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA8",
        name="ephi_export_without_audit",
        description="Bulk export patient data via API endpoints that bypass the audit "
                    "logging system, leaving no trace of data access.",
        detection_signals=[
            "/export", "/download", "/bulk", "/report", "/fhir",
            "format=csv", "format=json", "all_patients",
        ],
        test_methodology=[
            "1. Find data export or bulk download endpoints",
            "2. Request a bulk export of patient data",
            "3. Verify if the export appears in audit logs",
            "4. Test FHIR bulk data endpoints ($export)",
            "5. Check if rate limiting exists on export endpoints",
        ],
        impact="Undetected mass PHI exfiltration - regulatory nightmare",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA5",
        name="consent_bypass",
        description="Access patient data without an active consent record. The system fails "
                    "to check consent status before serving protected information.",
        detection_signals=[
            "/consent", "consent_id", "consent_status", "/patient",
            "authorization", "access_level",
        ],
        test_methodology=[
            "1. Identify consent management endpoints",
            "2. Revoke or never grant consent for a test patient",
            "3. Attempt to access the patient's data via clinical endpoints",
            "4. Check if consent is enforced at API vs UI level",
            "5. Test with expired consent records",
        ],
        impact="Access to data patient explicitly denied - consent violation",
        severity="high",
        bounty_range="$3K-$20K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA3",
        name="insurance_claim_manipulation",
        description="Modify insurance claim amounts, procedure codes, or diagnosis codes "
                    "to inflate reimbursement or alter claim outcomes.",
        detection_signals=[
            "/claim", "/insurance", "claim_id", "procedure_code",
            "diagnosis_code", "icd_code", "cpt_code", "amount",
        ],
        test_methodology=[
            "1. Submit or access an insurance claim",
            "2. Intercept and modify the claim amount upward",
            "3. Change procedure codes to higher-reimbursement codes",
            "4. Modify diagnosis codes (ICD-10) to alter claim category",
            "5. Check server-side validation of code-amount consistency",
        ],
        impact="Insurance fraud - inflated or fraudulent claims",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA7",
        name="role_escalation_ehr",
        description="Escalate from nurse/staff role to doctor/admin privileges in the EHR "
                    "system by manipulating role parameters or accessing restricted endpoints.",
        detection_signals=[
            "role", "role_id", "permission", "/admin", "/provider",
            "access_level", "privilege", "specialty",
        ],
        test_methodology=[
            "1. Authenticate as a low-privilege role (e.g. nurse)",
            "2. Attempt to access doctor-only endpoints (e.g. prescribe medication)",
            "3. Modify role_id or role parameter in requests",
            "4. Check JWT/session token for role claims - try modifying",
            "5. Test administrative functions (user management, system config)",
        ],
        impact="Unauthorized prescribing, record modification, system control",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA10",
        name="hipaa_audit_log_tampering",
        description="Modify or delete entries in the HIPAA-required audit log to cover "
                    "tracks after unauthorized data access.",
        detection_signals=[
            "/audit", "/log", "audit_id", "log_entry",
            "/audit-log", "event_id", "access_log",
        ],
        test_methodology=[
            "1. Perform an auditable action (view patient record)",
            "2. Find the audit log endpoint",
            "3. Attempt to DELETE specific audit entries",
            "4. Try PUT/PATCH to modify audit entries",
            "5. Check if audit logs are append-only or mutable",
        ],
        impact="Destroy forensic evidence of data breaches - regulatory violation",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="healthcare",
        category="BLA6",
        name="lab_result_manipulation",
        description="Modify lab results or diagnostic data by intercepting and altering "
                    "API requests between lab systems and the EHR.",
        detection_signals=[
            "/lab", "/result", "/diagnostic", "lab_id",
            "result_value", "test_code", "specimen_id",
        ],
        test_methodology=[
            "1. Identify lab result submission or retrieval endpoints",
            "2. Intercept a lab result response",
            "3. Modify result values (e.g. blood glucose level)",
            "4. Check if modified results are saved to patient record",
            "5. Test integrity verification on lab data",
        ],
        impact="Falsified medical data leading to wrong treatment decisions",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
]

_AUTOMOTIVE_PATTERNS: list[DomainPattern] = [
    DomainPattern(
        domain="automotive",
        category="BLA1",
        name="vehicle_command_injection",
        description="Send lock, unlock, or start commands to any vehicle via the API without "
                    "ownership verification. VIN or vehicle_id is the only authorization.",
        detection_signals=[
            "/vehicle", "/command", "/lock", "/unlock", "/start",
            "/engine", "vehicle_id", "vin", "command_type",
        ],
        test_methodology=[
            "1. Send a lock/unlock command for your own vehicle",
            "2. Capture the request and note parameters",
            "3. Change vehicle_id/VIN to another vehicle",
            "4. Send the command and check if it executes",
            "5. Test start engine, honk horn, flash lights commands",
        ],
        impact="Physical vehicle control - lock/unlock/start any car remotely",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA1",
        name="vin_based_idor",
        description="Access any vehicle's data by enumerating VINs. VINs follow a known "
                    "structure (17 chars, checksum digit) making enumeration feasible.",
        detection_signals=[
            "vin", "vehicle_identification_number", "/vehicle/",
            "/v1/vehicles", "vehicle_data",
        ],
        test_methodology=[
            "1. Access your vehicle's data endpoint with your VIN",
            "2. Generate valid VINs (follow WMI + VDS + VIS structure)",
            "3. Query the API with other valid VINs",
            "4. Check what data is returned (location, mileage, owner info)",
            "5. Test batch/bulk endpoints if available",
        ],
        impact="Mass vehicle data exposure - location tracking, owner PII",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA9",
        name="ota_update_mitm",
        description="Intercept over-the-air firmware updates and inject modified firmware. "
                    "Exploit missing signature verification or pinning.",
        detection_signals=[
            "/update", "/firmware", "/ota", "firmware_version",
            "update_url", "checksum", "signature",
        ],
        test_methodology=[
            "1. Monitor vehicle's update check mechanism",
            "2. Intercept the update manifest/metadata request",
            "3. Check if HTTPS certificate pinning is enforced",
            "4. Modify the update URL to point to attacker server",
            "5. Check if firmware signature is validated before installation",
        ],
        impact="Arbitrary code execution on vehicle systems - safety critical",
        severity="critical",
        bounty_range="$15K-$100K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA1",
        name="gps_tracking_access",
        description="Read any vehicle's real-time location and location history by "
                    "accessing GPS/telemetry endpoints with manipulated vehicle IDs.",
        detection_signals=[
            "/location", "/gps", "/tracking", "/telemetry",
            "latitude", "longitude", "position", "trip_history",
        ],
        test_methodology=[
            "1. Access your vehicle's location endpoint",
            "2. Change vehicle_id to another vehicle's ID",
            "3. Request location history/trip data",
            "4. Check real-time tracking endpoints",
            "5. Test geofence and notification endpoints",
        ],
        impact="Stalking capability - track any vehicle in real-time",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA7",
        name="dealer_portal_access",
        description="Access dealer management portal via weak authentication, default "
                    "credentials, or privilege escalation from customer account.",
        detection_signals=[
            "/dealer", "/admin", "/portal", "/management",
            "dealer_id", "dealer_code", "staff_login",
        ],
        test_methodology=[
            "1. Identify dealer portal URLs (common paths: /dealer, /admin)",
            "2. Test default credentials (admin/admin, dealer/dealer)",
            "3. Check if customer JWT works on dealer endpoints",
            "4. Test for role parameter manipulation",
            "5. Check for exposed dealer API documentation",
        ],
        impact="Access to all customer data, vehicle controls, pricing systems",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA1",
        name="telematics_data_exposure",
        description="Access driving data, diagnostics, and maintenance records for any "
                    "vehicle via IDOR on telematics endpoints.",
        detection_signals=[
            "/telematics", "/diagnostics", "/dtc", "/obd",
            "/maintenance", "vehicle_health", "driving_score",
        ],
        test_methodology=[
            "1. Access your vehicle's telematics data",
            "2. Change vehicle/owner identifiers",
            "3. Request diagnostic trouble codes (DTCs)",
            "4. Access driving behavior data (speed, braking, acceleration)",
            "5. Check maintenance history and service records",
        ],
        impact="Privacy violation - driving habits, vehicle condition, location patterns",
        severity="high",
        bounty_range="$3K-$15K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA8",
        name="remote_diagnostic_abuse",
        description="Trigger diagnostic modes remotely that could affect vehicle operation, "
                    "such as disabling traction control or entering test mode.",
        detection_signals=[
            "/diagnostic", "/service-mode", "/test-mode",
            "diagnostic_command", "dtc_clear", "ecu_reset",
        ],
        test_methodology=[
            "1. Identify diagnostic command endpoints in the API",
            "2. Send diagnostic commands to your own vehicle",
            "3. Test if commands work on other vehicle IDs",
            "4. Attempt to trigger service/test modes remotely",
            "5. Check for safety-critical command restrictions",
        ],
        impact="Safety risk - remotely alter vehicle behavior while driving",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="automotive",
        category="BLA7",
        name="fleet_management_escalation",
        description="Access other organizations' fleet data by manipulating tenant/org "
                    "identifiers in fleet management APIs.",
        detection_signals=[
            "/fleet", "/organization", "/company", "org_id",
            "fleet_id", "company_id", "tenant",
        ],
        test_methodology=[
            "1. Authenticate to fleet management as your organization",
            "2. Change org_id/fleet_id/tenant parameter",
            "3. Request vehicle list for another organization",
            "4. Access their fleet analytics and reports",
            "5. Test vehicle command execution across tenants",
        ],
        impact="Cross-tenant data breach - competitor fleet data, vehicle controls",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
]

_SOCIAL_PATTERNS: list[DomainPattern] = [
    DomainPattern(
        domain="social",
        category="BLA1",
        name="private_message_idor",
        description="Read other users' private messages by manipulating message or "
                    "conversation IDs in the API request.",
        detection_signals=[
            "/message", "/dm", "/conversation", "/chat",
            "message_id", "conversation_id", "thread_id",
        ],
        test_methodology=[
            "1. Access your own message/conversation",
            "2. Note the ID format (numeric, UUID, etc.)",
            "3. Modify the ID to access other conversations",
            "4. Test with incremented, decremented, and random IDs",
            "5. Check both individual message and full conversation endpoints",
        ],
        impact="Mass private message exposure - PII, secrets, intimate content",
        severity="critical",
        bounty_range="$5K-$30K",
    ),
    DomainPattern(
        domain="social",
        category="BLA4",
        name="block_bypass",
        description="Send messages or interact with users who have blocked you by using "
                    "alternative API endpoints or parameter manipulation.",
        detection_signals=[
            "/message", "/send", "/comment", "/react",
            "blocked", "block_list", "recipient_id",
        ],
        test_methodology=[
            "1. Have user B block user A",
            "2. As user A, try direct message via API (bypass UI block check)",
            "3. Test group message including blocked user",
            "4. Try reactions, comments, mentions of blocked user",
            "5. Test if blocked user appears in search results",
        ],
        impact="Harassment and stalking vector - safety feature bypass",
        severity="high",
        bounty_range="$2K-$10K",
    ),
    DomainPattern(
        domain="social",
        category="BLA6",
        name="account_impersonation",
        description="Manipulate display name, avatar, or verification status to perfectly "
                    "mimic another user for social engineering.",
        detection_signals=[
            "/profile", "/settings", "display_name", "username",
            "avatar_url", "verified", "badge",
        ],
        test_methodology=[
            "1. Attempt to set display_name identical to a target user",
            "2. Check if Unicode homoglyphs are filtered",
            "3. Try setting verified/badge fields via API",
            "4. Copy exact avatar URL from target profile",
            "5. Test if profile appears identical to target in messages/search",
        ],
        impact="Social engineering, phishing, reputation damage",
        severity="high",
        bounty_range="$2K-$10K",
    ),
    DomainPattern(
        domain="social",
        category="BLA5",
        name="group_channel_escalation",
        description="Join private groups, channels, or communities without an invitation "
                    "by manipulating join requests or group IDs.",
        detection_signals=[
            "/group", "/channel", "/community", "/join",
            "group_id", "channel_id", "invite_code", "private",
        ],
        test_methodology=[
            "1. Identify private group/channel endpoints",
            "2. Send a join request with the group_id directly",
            "3. Enumerate group IDs to find private groups",
            "4. Test if invite codes are validated or just decorative",
            "5. Check if you can access group content without joining",
        ],
        impact="Access to private communities - corporate secrets, private discussions",
        severity="high",
        bounty_range="$3K-$15K",
    ),
    DomainPattern(
        domain="social",
        category="BLA1",
        name="media_file_idor",
        description="Access private photos, videos, or files by manipulating media "
                    "IDs or direct URLs that lack access control.",
        detection_signals=[
            "/media", "/photo", "/video", "/file", "/attachment",
            "media_id", "file_id", "cdn", "storage",
        ],
        test_methodology=[
            "1. Upload a private media file and note its URL/ID",
            "2. Check if URL is guessable or sequential",
            "3. Access media URLs without authentication",
            "4. Enumerate media IDs to find other users' private files",
            "5. Test if CDN URLs have expiring signatures",
        ],
        impact="Private photo/video exposure - intimate content, corporate docs",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="social",
        category="BLA6",
        name="notification_manipulation",
        description="Trigger notifications as another user or manipulate notification "
                    "content to deliver phishing messages via trusted channels.",
        detection_signals=[
            "/notification", "/notify", "/push", "notification_id",
            "sender_id", "push_token",
        ],
        test_methodology=[
            "1. Identify notification trigger mechanisms",
            "2. Intercept notification request and change sender_id",
            "3. Test if custom notification content can be injected",
            "4. Check push notification endpoints for auth bypass",
            "5. Try triggering admin/system notifications as regular user",
        ],
        impact="Phishing via trusted notification channel, spam, harassment",
        severity="high",
        bounty_range="$2K-$10K",
    ),
    DomainPattern(
        domain="social",
        category="BLA3",
        name="profile_data_exposure",
        description="API returns more user profile fields than the UI displays, leaking "
                    "email, phone, location, or other sensitive data.",
        detection_signals=[
            "/profile", "/user", "/account", "email", "phone",
            "address", "date_of_birth", "ssn",
        ],
        test_methodology=[
            "1. Request a user's profile via API",
            "2. Compare API response fields to what the UI shows",
            "3. Check for hidden fields: email, phone, IP, location",
            "4. Test GraphQL introspection for extra fields",
            "5. Use field projection/selection to request specific hidden fields",
        ],
        impact="PII exposure - email, phone, address of any user",
        severity="high",
        bounty_range="$2K-$15K",
    ),
    DomainPattern(
        domain="social",
        category="BLA10",
        name="content_moderation_bypass",
        description="Evade content filters via Unicode tricks, homoglyphs, zero-width "
                    "characters, image steganography, or encoding manipulation.",
        detection_signals=[
            "/post", "/comment", "/message", "content",
            "text", "body", "filter", "moderation",
        ],
        test_methodology=[
            "1. Submit content that should be filtered (test with known bad words)",
            "2. Try Unicode homoglyphs (e.g. Cyrillic 'a' instead of Latin 'a')",
            "3. Insert zero-width characters between letters",
            "4. Test base64/URL encoding in text fields",
            "5. Try right-to-left override characters to hide content",
        ],
        impact="Bypass safety systems - hate speech, harassment, illegal content",
        severity="medium",
        bounty_range="$1K-$5K",
    ),
    DomainPattern(
        domain="social",
        category="BLA4",
        name="read_receipt_manipulation",
        description="Mark messages as read/unread for other users or access read receipt "
                    "data to determine if a user has seen a specific message.",
        detection_signals=[
            "/read", "/seen", "/receipt", "read_at",
            "seen_by", "delivered_at",
        ],
        test_methodology=[
            "1. Send a message and note the read receipt endpoint",
            "2. Try marking messages in other conversations as read",
            "3. Access read receipt data for conversations you're not in",
            "4. Manipulate read timestamps",
            "5. Check if read receipts are enforced server-side",
        ],
        impact="Privacy violation - surveillance of reading habits",
        severity="medium",
        bounty_range="$500-$3K",
    ),
]

_SAAS_PATTERNS: list[DomainPattern] = [
    DomainPattern(
        domain="saas",
        category="BLA1",
        name="multi_tenant_isolation_bypass",
        description="Access another organization's data by manipulating tenant ID, "
                    "organization ID, or workspace parameters in API requests.",
        detection_signals=[
            "tenant_id", "org_id", "organization_id", "workspace_id",
            "company_id", "/org/", "/tenant/", "X-Tenant-ID",
        ],
        test_methodology=[
            "1. Authenticate as user in Organization A",
            "2. Note your tenant_id/org_id in requests",
            "3. Change to Organization B's tenant_id",
            "4. Request data (users, documents, settings)",
            "5. Test with headers (X-Tenant-ID) and URL path parameters",
        ],
        impact="Full cross-tenant data breach - access all customer data",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA5",
        name="api_versioning_confusion",
        description="Older API versions (v1) lack authentication or authorization that "
                    "newer versions (v2+) enforce. Access v1 endpoints to bypass security.",
        detection_signals=[
            "/v1/", "/v2/", "/api/v1", "/api/v2", "api-version",
            "version", "deprecated",
        ],
        test_methodology=[
            "1. Map available API versions (v1, v2, v3, etc.)",
            "2. Find endpoints that exist in multiple versions",
            "3. Test v1 endpoints without authentication",
            "4. Compare response fields between versions",
            "5. Check if deprecated versions are still accessible",
        ],
        impact="Auth bypass via legacy API - access data without credentials",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA2",
        name="invitation_code_reuse",
        description="Single-use invitation codes can be used multiple times due to "
                    "missing or race-condition-vulnerable invalidation.",
        detection_signals=[
            "/invite", "/invitation", "invite_code", "invite_token",
            "invitation_id", "/join",
        ],
        test_methodology=[
            "1. Generate a single-use invitation code",
            "2. Use the code to join/register once",
            "3. Attempt to reuse the same code",
            "4. Send concurrent join requests with the same code",
            "5. Check if expired invites are still accepted",
        ],
        impact="Unauthorized access to organizations via recycled invites",
        severity="high",
        bounty_range="$2K-$10K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA6",
        name="trial_extension",
        description="Re-register with the same or aliased email to get unlimited trial "
                    "periods, bypassing trial-once enforcement.",
        detection_signals=[
            "/trial", "/register", "/signup", "trial_end",
            "trial_days", "plan_type", "subscription_status",
        ],
        test_methodology=[
            "1. Register for a free trial",
            "2. Let the trial expire",
            "3. Re-register with email+alias (user+1@gmail.com)",
            "4. Check if a new trial is granted",
            "5. Test with different browser fingerprints",
        ],
        impact="Permanent free access - revenue loss from never-converting trials",
        severity="medium",
        bounty_range="$500-$3K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA7",
        name="feature_flag_manipulation",
        description="Enable premium features by manipulating feature flags stored in "
                    "cookies, headers, local storage, or request parameters.",
        detection_signals=[
            "feature", "flag", "premium", "plan", "tier",
            "X-Feature-Flags", "features_enabled", "entitlements",
        ],
        test_methodology=[
            "1. Inspect cookies and local storage for feature flags",
            "2. Check response headers for feature/plan information",
            "3. Modify feature flag values (premium=true, tier=enterprise)",
            "4. Test if server validates feature access or trusts client",
            "5. Check JWT claims for feature/plan fields",
        ],
        impact="Premium features for free - full platform access at free tier",
        severity="high",
        bounty_range="$2K-$15K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA7",
        name="admin_panel_access",
        description="Regular user reaches admin endpoints due to missing role-based "
                    "access control on admin API routes.",
        detection_signals=[
            "/admin", "/internal", "/management", "/dashboard",
            "/settings/global", "is_admin", "role",
        ],
        test_methodology=[
            "1. Enumerate common admin paths (/admin, /internal, /manage)",
            "2. Access admin API endpoints with regular user token",
            "3. Test admin actions (user management, billing, config)",
            "4. Check if admin UI is hidden but API is accessible",
            "5. Try adding admin role to your JWT/session",
        ],
        impact="Full platform takeover - admin control over all tenants",
        severity="critical",
        bounty_range="$10K-$50K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA8",
        name="webhook_data_exposure",
        description="Webhook payloads contain other tenants' data due to shared "
                    "webhook infrastructure without tenant isolation.",
        detection_signals=[
            "/webhook", "webhook_url", "callback_url", "event_type",
            "webhook_secret", "payload",
        ],
        test_methodology=[
            "1. Configure a webhook endpoint (use webhook.site or similar)",
            "2. Trigger events that fire webhooks",
            "3. Inspect webhook payloads for data from other tenants",
            "4. Register webhooks for event types of other tenants",
            "5. Check if webhook secrets are properly scoped per tenant",
        ],
        impact="Passive data leakage - receive other customers' data via webhooks",
        severity="critical",
        bounty_range="$5K-$25K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA5",
        name="sso_bypass",
        description="Access the application without completing the SSO flow by using "
                    "direct API authentication or legacy login endpoints.",
        detection_signals=[
            "/sso", "/saml", "/oauth", "/login", "/auth",
            "sso_required", "idp", "saml_response",
        ],
        test_methodology=[
            "1. Identify if SSO is required for the organization",
            "2. Try direct username/password login (bypass SSO)",
            "3. Access API endpoints directly with API keys",
            "4. Test password reset flow (does it bypass SSO?)",
            "5. Check mobile app authentication (often skips SSO)",
        ],
        impact="Bypass SSO security controls - access without MFA/compliance checks",
        severity="high",
        bounty_range="$3K-$15K",
    ),
    DomainPattern(
        domain="saas",
        category="BLA3",
        name="rate_limit_bypass_per_tenant",
        description="Rate limits are applied globally rather than per-tenant, allowing "
                    "one tenant to consume another tenant's API quota.",
        detection_signals=[
            "rate_limit", "X-RateLimit", "429", "quota",
            "throttle", "requests_remaining",
        ],
        test_methodology=[
            "1. Identify rate limit headers in responses",
            "2. Exhaust the rate limit from one tenant account",
            "3. Check if other tenants are also rate-limited",
            "4. Test if rate limits apply per-user or per-tenant",
            "5. Attempt to DoS other tenants by consuming shared quota",
        ],
        impact="Denial of service to other tenants via shared rate limiting",
        severity="high",
        bounty_range="$2K-$10K",
    ),
]


class DomainKnowledge:
    """Domain-specific vulnerability knowledge for automated security testing.

    Provides pattern detection, domain classification, and hypothesis
    generation for business logic vulnerabilities across six major domains.
    """

    DOMAIN_PATTERNS: dict[str, list[DomainPattern]] = {
        "fintech": _FINTECH_PATTERNS,
        "ecommerce": _ECOMMERCE_PATTERNS,
        "healthcare": _HEALTHCARE_PATTERNS,
        "automotive": _AUTOMOTIVE_PATTERNS,
        "social": _SOCIAL_PATTERNS,
        "saas": _SAAS_PATTERNS,
    }

    # Keyword-to-domain mapping for detection
    _URL_KEYWORDS: dict[str, list[str]] = {
        "fintech": [
            "transfer", "withdraw", "deposit", "balance", "payment",
            "bank", "wallet", "loan", "invest", "trade", "forex",
            "crypto", "ledger", "fund", "wire",
        ],
        "ecommerce": [
            "checkout", "cart", "order", "product", "shop", "store",
            "catalog", "shipping", "coupon", "discount", "inventory",
            "wishlist", "buy", "purchase",
        ],
        "healthcare": [
            "patient", "medical", "health", "prescription", "rx",
            "appointment", "clinical", "diagnosis", "ehr", "fhir",
            "hl7", "dicom", "lab", "pharmacy", "provider",
        ],
        "automotive": [
            "vehicle", "car", "vin", "telematics", "obd", "dtc",
            "fleet", "drive", "engine", "firmware", "ota",
            "connected-car", "infotainment",
        ],
        "social": [
            "message", "chat", "dm", "post", "comment", "feed",
            "friend", "follow", "profile", "notification", "group",
            "channel", "community", "story", "reaction",
        ],
        "saas": [
            "tenant", "organization", "workspace", "team", "admin",
            "dashboard", "api-key", "webhook", "integration",
            "subscription", "billing", "sso", "saml", "oauth",
        ],
    }

    _TECH_INDICATORS: dict[str, list[str]] = {
        "fintech": ["stripe", "plaid", "dwolla", "wise", "adyen", "braintree"],
        "ecommerce": ["shopify", "magento", "woocommerce", "bigcommerce", "saleor"],
        "healthcare": ["fhir", "hl7", "epic", "cerner", "allscripts", "athenahealth"],
        "automotive": ["can", "obd", "mqtt", "canbus", "j1939", "autosar"],
        "social": ["firebase", "pusher", "socket.io", "websocket", "xmpp"],
        "saas": ["auth0", "okta", "onelogin", "workos", "clerk"],
    }

    def __init__(self) -> None:
        """Initialize domain knowledge with all pattern data."""
        # Pre-compute a flat list for cross-domain searches
        self._all_patterns: list[DomainPattern] = []
        for patterns in self.DOMAIN_PATTERNS.values():
            self._all_patterns.extend(patterns)

    def detect_domain(
        self,
        url: str,
        endpoints: list[str],
        tech_stack: dict[str, Any],
        page_content: str = "",
    ) -> str:
        """Auto-detect the business domain from application signals.

        Scores each domain based on URL keywords, endpoint patterns,
        tech stack indicators, and page content. Returns the highest-scoring
        domain name.

        Args:
            url: Target URL.
            endpoints: List of discovered API endpoint paths.
            tech_stack: Dict of identified technologies (keys are tech names).
            page_content: Optional page text content for keyword analysis.

        Returns:
            Detected domain name (fintech, ecommerce, healthcare,
            automotive, social, saas). Defaults to "saas" if no clear signal.
        """
        scores: dict[str, int] = {d: 0 for d in self.DOMAIN_PATTERNS}
        combined_text = (
            url.lower()
            + " "
            + " ".join(endpoints).lower()
            + " "
            + page_content.lower()
        )

        # Score URL/endpoint/content keywords
        for domain, keywords in self._URL_KEYWORDS.items():
            for kw in keywords:
                if kw in combined_text:
                    scores[domain] += 2

        # Score tech stack indicators
        tech_str = " ".join(str(k).lower() + " " + str(v).lower() for k, v in tech_stack.items())
        for domain, indicators in self._TECH_INDICATORS.items():
            for indicator in indicators:
                if indicator in tech_str:
                    scores[domain] += 5  # Strong signal

        # Pick the highest scoring domain
        best_domain = max(scores, key=lambda d: scores[d])
        if scores[best_domain] == 0:
            return "saas"  # Default fallback
        return best_domain

    def get_patterns(self, domain: str) -> list[DomainPattern]:
        """Get all vulnerability patterns for a domain.

        Args:
            domain: Domain name (fintech, ecommerce, healthcare,
                    automotive, social, saas).

        Returns:
            List of DomainPattern objects for the domain.
            Empty list if domain is unknown.
        """
        return self.DOMAIN_PATTERNS.get(domain, [])

    def get_patterns_for_endpoint(
        self,
        domain: str,
        endpoint: str,
        method: str,
    ) -> list[DomainPattern]:
        """Filter patterns relevant to a specific endpoint.

        Matches patterns whose detection_signals appear in the endpoint
        path or HTTP method context.

        Args:
            domain: Domain name.
            endpoint: API endpoint path (e.g. "/api/v1/transfer").
            method: HTTP method (GET, POST, PUT, DELETE, etc.).

        Returns:
            List of matching DomainPattern objects sorted by severity.
        """
        patterns = self.get_patterns(domain)
        endpoint_lower = endpoint.lower()
        method_lower = method.lower()
        matched: list[DomainPattern] = []

        for pattern in patterns:
            for signal in pattern.detection_signals:
                signal_lower = signal.lower()
                if signal_lower in endpoint_lower or signal_lower in method_lower:
                    matched.append(pattern)
                    break

        severity_order = {"critical": 0, "high": 1, "medium": 2}
        matched.sort(key=lambda p: severity_order.get(p.severity, 3))
        return matched

    def patterns_to_hypotheses(
        self,
        patterns: list[DomainPattern],
        target_url: str,
    ) -> list[dict[str, Any]]:
        """Convert domain patterns into attack graph hypothesis format.

        Generates hypothesis dicts compatible with the attack graph
        engine's expected format.

        Args:
            patterns: List of DomainPattern objects to convert.
            target_url: Base URL of the target application.

        Returns:
            List of hypothesis dicts with keys: id, name, description,
            category, severity, test_steps, target, domain, bounty_range.
        """
        hypotheses: list[dict[str, Any]] = []
        for i, pattern in enumerate(patterns):
            hypothesis = {
                "id": f"domain_{pattern.domain}_{pattern.name}_{i}",
                "name": pattern.name,
                "description": pattern.description,
                "category": pattern.category,
                "severity": pattern.severity,
                "test_steps": pattern.test_methodology,
                "detection_signals": pattern.detection_signals,
                "target": target_url,
                "domain": pattern.domain,
                "bounty_range": pattern.bounty_range,
                "impact": pattern.impact,
                "source": "domain_knowledge_pack_v4",
            }
            hypotheses.append(hypothesis)
        return hypotheses

    def get_bla_category(self, category: str) -> list[DomainPattern]:
        """Get all patterns matching a specific OWASP BLA category.

        Searches across all domains for patterns in the given category.

        Args:
            category: BLA category string (e.g. "BLA1", "BLA2").

        Returns:
            List of DomainPattern objects matching the category.
        """
        category_upper = category.upper()
        return [p for p in self._all_patterns if p.category.upper() == category_upper]

    def format_domain_context(self, domain: str, max_chars: int = 2000) -> str:
        """Format domain knowledge as context for LLM prompt injection.

        Produces a compact summary of domain patterns suitable for
        including in an LLM prompt to guide testing strategy.

        Args:
            domain: Domain name.
            max_chars: Maximum character length for the output.

        Returns:
            Formatted string summarizing domain patterns within max_chars.
        """
        patterns = self.get_patterns(domain)
        if not patterns:
            return f"No domain knowledge available for '{domain}'."

        lines: list[str] = [
            f"## Domain: {domain.upper()} - Business Logic Attack Patterns",
            f"Total patterns: {len(patterns)}",
            "",
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2}
        sorted_patterns = sorted(
            patterns, key=lambda p: severity_order.get(p.severity, 3)
        )

        for pattern in sorted_patterns:
            entry = (
                f"### {pattern.name} [{pattern.severity.upper()}] ({pattern.category})\n"
                f"{pattern.description}\n"
                f"Signals: {', '.join(pattern.detection_signals[:5])}\n"
                f"Impact: {pattern.impact}\n"
                f"Bounty: {pattern.bounty_range}\n"
            )
            # Check if adding this entry would exceed limit
            current_length = sum(len(line) + 1 for line in lines)
            if current_length + len(entry) > max_chars:
                lines.append(
                    f"... ({len(sorted_patterns) - sorted_patterns.index(pattern)} "
                    f"more patterns truncated)"
                )
                break
            lines.append(entry)

        return "\n".join(lines)
