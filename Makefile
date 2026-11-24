include $(TOPDIR)/rules.mk

PKG_NAME:=rtl9617c-pon-control
PKG_VERSION:=0.11.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-or-later

include $(INCLUDE_DIR)/package.mk

define Package/rtl9617c-pon-control
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Native RTL9617C PON identity, EPON OAM and ITU OMCI control
  DEPENDS:=+libuci +libgcc +ucode +ucode-mod-fs
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
	mkdir -p $(PKG_BUILD_DIR)/omci/src
	$(CP) ./omci/Cargo.toml ./omci/Cargo.lock ./omci/LICENSE ./omci/UPSTREAM $(PKG_BUILD_DIR)/omci/
	$(CP) ./omci/src/* $(PKG_BUILD_DIR)/omci/src/
endef

RTL9617C_CARGO?=$(firstword $(wildcard $(HOME)/.cargo/bin/cargo) $(shell command -v cargo))
RTL9617C_RUST_TARGET?=$(ARCH)-unknown-linux-musl
RTL9617C_RUST_CPU?=cortex-a53
PON_CFLAGS:=-std=gnu11 -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wundef \
	-Wcast-align -Wstrict-prototypes
define Build/Compile
	cd $(PKG_BUILD_DIR)/omci && RUSTC="$(dir $(RTL9617C_CARGO))rustc" \
		RUSTFLAGS="-C target-cpu=$(RTL9617C_RUST_CPU)" $(RTL9617C_CARGO) build --release --locked \
		--target $(RTL9617C_RUST_TARGET)
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(PON_CFLAGS) \
		-DPON_FIRMWARE_VERSION='"$(PKG_VERSION)"' \
		$(PKG_BUILD_DIR)/pon-oamd.c $(PKG_BUILD_DIR)/pon-oam.c $(PKG_BUILD_DIR)/pon-backend.c \
		$(PKG_BUILD_DIR)/pon-events.c \
		$(TARGET_LDFLAGS) -luci -o $(PKG_BUILD_DIR)/pon-oamd
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(PON_CFLAGS) \
		$(PKG_BUILD_DIR)/pon-identity.c $(PKG_BUILD_DIR)/pon-events.c \
		$(PKG_BUILD_DIR)/pon-sha256.c $(TARGET_LDFLAGS) -luci -o $(PKG_BUILD_DIR)/pon-identity
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(PON_CFLAGS) \
		$(PKG_BUILD_DIR)/pon-status.c $(PKG_BUILD_DIR)/pon-events.c $(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/pon-status
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(PON_CFLAGS) \
		-DPON_FIRMWARE_VERSION='"$(PKG_VERSION)"' \
		$(PKG_BUILD_DIR)/pon-omcid.c $(PKG_BUILD_DIR)/pon-events.c \
		$(PKG_BUILD_DIR)/omci/target/$(RTL9617C_RUST_TARGET)/release/librtl9617c_omci.a \
		$(TARGET_LDFLAGS) -luci -lgcc_s -lpthread -lm -ldl -o $(PKG_BUILD_DIR)/pon-omcid
endef

define Package/rtl9617c-pon-control/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pon-oamd $(1)/usr/sbin/pon-oamd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pon-identity $(1)/usr/sbin/pon-identity
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pon-omcid $(1)/usr/sbin/pon-omcid
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pon-status $(1)/usr/sbin/pon-status
	$(INSTALL_DIR) $(1)/usr/share/rtl9617c
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/etc/config/pon $(1)/etc/config/pon
	$(INSTALL_BIN) ./files/pon-leds.uc $(1)/usr/share/rtl9617c/pon-leds.uc
	$(INSTALL_DATA) ./omci/UPSTREAM $(1)/usr/share/rtl9617c/omci-UPSTREAM
	$(INSTALL_BIN) ./files/etc/init.d/pon $(1)/etc/init.d/pon
	$(INSTALL_BIN) ./files/etc/init.d/pon-leds $(1)/etc/init.d/pon-leds
	$(INSTALL_BIN) ./files/usr/share/rtl9617c/rename-netdevs.uc $(1)/etc/uci-defaults/89-rtl9617c-lan-ports
endef

$(eval $(call BuildPackage,rtl9617c-pon-control))
