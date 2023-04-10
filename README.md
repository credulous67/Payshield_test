# Payshield_test
Credit to Marco Simone Zuppone (https://github.com/mszeu/PayShieldPressureTest) for inspiration, and some code!!

Identify the HSM being targeted

This is a script to run through a series of typical payment HSM tasks
1. Generate test cards
2. Generate required keys (ZPK, PVK, CVK, RSA keypair)
3. Generate test hashes for test message
4. Generate RSA signature for test message
5. Validate RSA signature

For each card do the following
1. Generate and validate CVV
2. Derive IBM natural PIN, translate pinblock, validate pin
3. Generate random PIN, translate pinblock, validate pin
4. Generate Visa PVV, validate pin (uses random pin from above)
