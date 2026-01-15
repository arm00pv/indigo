def get_duress_otp(otp: str) -> str:
    """
    Transforms a standard OTP into a Duress OTP.
    Logic: Increment the last digit by 1 (wrapping 0-9).
    Example: 123456 -> 123457
             123459 -> 123450
    """
    if not otp or not otp.isdigit():
        return otp

    last_digit = int(otp[-1])
    new_last_digit = (last_digit + 1) % 10
    return otp[:-1] + str(new_last_digit)
