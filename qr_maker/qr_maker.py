import qrcode
from qrcode.constants import (  # noqa
    ERROR_CORRECT_L,
    ERROR_CORRECT_M,
    ERROR_CORRECT_Q,
    ERROR_CORRECT_H,
)
import base64

device_data = bytearray([
    # 33bytes compressed public key
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22,
    
    # 16bytes passcode
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    
    # 20bytes function 1 - getTemp() -> number
    ord('g'), ord('e'), ord('t'), ord('T'), ord('e'), ord('m'), ord('p'), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x02,  # no args, returns number
    
    # 20bytes function 2 - setLED(number,Boolean) -> void
    ord('s'), ord('e'), ord('t'), ord('L'), ord('E'), ord('D'), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xb0, 0x00   # number,Boolean args, returns void
])

device_data_text:str = device_data.decode('latin-1', errors='ignore')

# QR 코드 생성
qr = qrcode.QRCode(
    version=None,  # 자동으로 최적 버전 선택
    error_correction=ERROR_CORRECT_L,  # 높은 수준의 오류 정정
    box_size=10,  # QR 코드의 각 박스 크기
    border=4,  # QR 코드 주변의 여백
)

# 데이터 추가
qr.add_data(device_data_text)
qr.make(fit=True)

# QR 코드 이미지 생성
qr_image = qr.make_image(fill_color="black", back_color="white")

# 이미지 저장
qr_image.save("device_data_qr.png")

print("QR 코드가 'device_data_qr.png' 파일로 저장되었습니다.")
