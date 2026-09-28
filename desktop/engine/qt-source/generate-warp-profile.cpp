std::shared_ptr<Profile> getWarpProfile() {
            const auto &settings = *dataManager->settingsRepo;
            auto warpProfile = std::make_shared<Profile>();
            warpProfile->name = "warp";
            warpProfile->id = warpProfileID;
            warpProfile->type = "wireguard";
            auto outbound = std::make_shared<wireguard>();
            outbound->name = "warp";
            outbound->server = settings.warp_ep.contains(":") ? SubStrBefore(settings.warp_ep, ":") : settings.warp_ep;
            outbound->server_port = settings.warp_ep.contains(":") ? SubStrAfter(settings.warp_ep, ":").toInt() : 2408;
            outbound->private_key = settings.warp_private_key;
            outbound->address = settings.warp_ifc_addrs;
            auto peer = std::make_shared<Peer>();
            peer->public_key = settings.warp_public_key;
            peer->address = outbound->server;
            peer->port = outbound->server_port;
            peer->reserved = QStringList2QListInt(settings.warp_reserved);
            peer->persistent_keepalive = "10";
            outbound->peer = peer;
            outbound->mtu = 1280;

            warpProfile->outbound = outbound;
            return warpProfile;
        }
