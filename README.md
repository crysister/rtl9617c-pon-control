# rtl9617c-pon-control

Native userspace PON control suite for Realtek RTL9617C (Taurus) OpenWrt / ImmortalWrt targets:

- `pon-oamd`: EPON OAM daemon (CTC/China Telecom auth & LOID/SN provisioning)
- `pon-omcid`: GPON / XG-PON / XGS-PON OMCI daemon (Rust `omci` library + C wrapper)
- `pon-identity`: PON identity / MAC / SN configuration helper
- `pon-status`: Optical transceiver & PON registration status query CLI
- `pon-leds`: PON/LOS/Internet LED controller (`ucode`)
- `89-rtl9617c-lan-ports`: LAN interface renaming (`uci-defaults`)

Aggregated into the OpenWrt / ImmortalWrt feed [crysister/rtl9617c-packages](https://github.com/crysister/rtl9617c-packages).
