void GroupUpdater::refresh(int gid, bool showDiff) {
        auto &settings = Configs::dataManager->settingsRepo;
        auto &profilesRepo = Configs::dataManager->profilesRepo;
        auto &groupsRepo = Configs::dataManager->groupsRepo;

        settings->imported_count = 0;
        auto group = groupsRepo->GetGroup(gid);
        if (group == nullptr || group->archive) return;

        QByteArray body;
        QString userInfo;
        if (!fetch(group->url.trimmed(), group->name, body, userInfo)) return;

        group->sub_last_update = QDateTime::currentMSecsSinceEpoch() / 1000;
        group->info = userInfo;
        groupsRepo->Save(group);

        // Auto selectors are local state, not servers the remote sent: keep them out of the diff.
        const auto selectorIds = profilesRepo->GetProfileIdsByType("autoselector");
        const QSet<int> selectors(selectorIds.begin(), selectorIds.end());
        QList<QPair<int, int>> sticky;
        QSet<int> stickyIDs;
        for (int i = 0; i < group->profiles.size(); i++) {
            if (!selectors.contains(group->profiles[i])) continue;
            sticky << qMakePair(i, group->profiles[i]);
            stickyIDs.insert(group->profiles[i]);
        }
        const auto members = [&] {
            QList<int> ids;
            for (int id : group->profiles) {
                if (!stickyIDs.contains(id)) ids << id;
            }
            return ids;
        };

        // Ids a running auto selector can no longer trust: deleted, or same id with new settings.
        QList<int> disturbed;
        bool cleared = false;
        if (settings->sub_clear) {
            MW_show_log(QObject::tr("Clearing servers..."));
            const auto outcome = deleteProfiles(members());
            if (!outcome.ok) {
                runOnUiThread([] { MessageBoxWarning("Internal Error", "DB Error when deleting profiles, Please try again."); });
                return;
            }
            disturbed = outcome.deleted;
            // A survivor still belongs to the subscription: fall through to the diff.
            cleared = outcome.kept.isEmpty();
        }

        QList<OldEntry> old;
        if (!cleared) {
            const auto ids = members();
            for (qsizetype off = 0; off < ids.size(); off += Configs::BATCH_LIMIT_READ) {
                for (const auto &ent : profilesRepo->GetProfileBatch(ids.mid(off, Configs::BATCH_LIMIT_READ))) {
                    if (ent == nullptr) continue;
                    old.append({ent->id, {contentKeyOf(*ent), identityKeyOf(*ent)}, ent->outbound->DisplayTypeAndName()});
                }
            }
        }
        ContentIndex index(old);
        ImportSink sink(gid, cleared ? nullptr : &index);

        MW_show_log(">>>>>>>> " + QObject::tr("Processing subscription data..."));
        ParseDocument(std::move(body), sinkFor(sink));
        sink.flush();
        MW_show_log(">>>>>>>> " + QObject::tr("Process complete, applying..."));

        QString change_text;
        if (cleared) {
            if (sink.entries.size() >= 1000) {
                change_text += "[+] " + Int2String(sink.entries.size()) + " profiles\n";
            } else {
                for (const auto &entry : sink.entries) change_text += "[+] " + entry.display + "\n";
            }
        } else {
            const auto plan = Reconcile(old, sink.entries, index);
            for (const auto &[oldId, newId] : plan.updates) {
                auto oldEnt = profilesRepo->GetProfile(oldId);
                const auto newEnt = profilesRepo->GetProfile(newId);
                if (oldEnt != nullptr && newEnt != nullptr) {
                    oldEnt->outbound = newEnt->outbound;
                    oldEnt->name = oldEnt->outbound->name;
                    profilesRepo->Save(oldEnt);
                }
                disturbed << oldId;
            }

            const auto previousOrder = group->profiles;
            group->profiles = plan.order;
            for (const auto &[position, id] : sticky) {
                group->profiles.insert(std::min<qsizetype>(position, group->profiles.size()), id);
            }
            groupsRepo->Save(group);

            const auto outcome = deleteProfiles(plan.stale);
            if (!outcome.ok) {
                runOnUiThread([] { MessageBoxWarning("Internal error", "DB Error when deleting profiles, data may be corrupted"); });
            }
            disturbed << outcome.deleted;

            // Nothing rebuilds group->profiles from the rows: a survivor left out here is orphaned.
            QString notice_kept;
            for (int id : outcome.kept) {
                if (group->HasProfile(id)) continue;
                const auto position = previousOrder.indexOf(id);
                group->profiles.insert(position < 0 ? group->profiles.size()
                                                    : std::min<qsizetype>(position, group->profiles.size()), id);
                if (const auto ent = profilesRepo->GetProfile(id); ent != nullptr) {
                    notice_kept += "[=] " + ent->outbound->DisplayTypeAndName() + "\n";
                }
            }
            if (!outcome.kept.isEmpty()) groupsRepo->Save(group);

            change_text = "\n" + QObject::tr("Added %1 profiles:\n%2\nUpdated %3 profiles:\n%4\nDeleted %5 Profiles:\n%6")
                                     .arg(plan.added.size())
                                     .arg(notice(plan.added, "[+]", "added"))
                                     .arg(plan.updates.size())
                                     .arg(notice(plan.updated, "[~]", "updated"))
                                     .arg(plan.deleted.size())
                                     .arg(notice(plan.deleted, "[-]", "deleted"));
            if (!notice_kept.isEmpty()) {
                change_text += "\n" + QObject::tr("Still in use, so kept instead of deleted:\n%1").arg(notice_kept);
            }
            if (plan.added.isEmpty() && plan.updates.isEmpty() && plan.deleted.isEmpty()) change_text = QObject::tr("Nothing");
        }

        MW_show_log("<<<<<<<< " + QObject::tr("Change of %1:").arg(group->name) + "\n" + change_text);
        if (showDiff && settings->sub_show_change_popup) {
            const auto diffTitle = QObject::tr("Change of %1").arg(group->name);
            auto diffBody = change_text.trimmed();
            if (diffBody.isEmpty()) diffBody = QObject::tr("Nothing");
            runOnUiThread([diffTitle, diffBody] { MessageBoxScrollable(diffTitle, diffBody); });
        }
        // Auto selectors resolve members from the group at build time, so a refresh can invalidate an untouched one.
        QStringList selectorArgs{Int2String(group->id)};
        for (int id : disturbed) selectorArgs << Int2String(id);
        MW_dialog_message(MwMessage::SubscriptionGroupChanged, selectorArgs);
        MW_dialog_message(MwMessage::SubscriptionFinished, {MwArg::Quiet});
    }
