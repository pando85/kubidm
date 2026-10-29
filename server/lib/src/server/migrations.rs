use crate::prelude::*;

use crate::migration_data;
use kubidm_proto::internal::{
    // DomainUpgradeCheckItem as ProtoDomainUpgradeCheckItem,
    DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport,
    // DomainUpgradeCheckStatus as ProtoDomainUpgradeCheckStatus,
};

use super::ServerPhase;

impl QueryServer {
    #[instrument(level = "info", name = "system_initialisation", skip_all)]
    pub async fn initialise_helper(
        &self,
        ts: Duration,
        domain_target_level: DomainVersion,
    ) -> Result<(), OperationError> {
        // We need to perform this in a single transaction pass to prevent tainting
        // databases during upgrades.
        let mut write_txn = self.write(ts).await?;

        // Because we init the schema here, and commit, this reloads meaning
        // that the on-disk index meta has been loaded, so our subsequent
        // migrations will be correctly indexed.
        //
        // Remember, that this would normally mean that it's possible for schema
        // to be mis-indexed (IE we index the new schemas here before we read
        // the schema to tell us what's indexed), but because we have the in
        // mem schema that defines how schema is structured, and this is all
        // marked "system", then we won't have an issue here.
        if domain_target_level < DOMAIN_LEVEL_1_11 {
            // Check our database version - attempt to do an initial indexing
            // based on the in memory configuration. This ONLY triggers ONCE on
            // the very first run of the instance when the DB in newely created.
            //
            // NOTE: After DL_1_11 this is no longer needed since all the schema
            // is in memory, and we don't need these initial indexes in order
            // to speed up index loading.
            write_txn.upgrade_reindex(SYSTEM_INDEX_VERSION)?;

            // We don't create these in the DB after 1_11
            write_txn
                .initialise_schema_core()
                .and_then(|_| write_txn.reload())?;
        }

        // This is what tells us if the domain entry existed before or not. This
        // is now the primary method of migrations and version detection.
        let db_domain_version = match write_txn.internal_search_uuid(UUID_DOMAIN_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32(Attribute::Version).unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;

        debug!(?db_domain_version, "Before setting internal domain info");

        if db_domain_version == DOMAIN_LEVEL_0 {
            // This is here to catch when we increase domain levels but didn't create the migration
            // hooks. If this fails it probably means you need to add another migration hook
            // in the above.
            debug_assert!(domain_target_level <= DOMAIN_MAX_LEVEL);

            // Assert that we have a minimum creation level that is valid.
            const { assert!(DOMAIN_MIN_CREATION_LEVEL == DOMAIN_LEVEL_11) };

            // No domain info was present, so neither was the rest of the IDM. Bring up the
            // full IDM here.

            match domain_target_level {
                DOMAIN_LEVEL_11 => write_txn.migrate_domain_10_to_11()?,
                DOMAIN_LEVEL_12 => write_txn.migrate_domain_11_to_12()?,
                DOMAIN_LEVEL_13 => write_txn.migrate_domain_12_to_13()?,
                DOMAIN_LEVEL_14 => write_txn.migrate_domain_13_to_14()?,
                DOMAIN_LEVEL_1_11 => write_txn.migrate_domain_1_10_to_1_11()?,
                DOMAIN_LEVEL_1_12 => write_txn.migrate_domain_1_11_to_1_12()?,
                DOMAIN_LEVEL_1_13 => write_txn.migrate_domain_1_12_to_1_13()?,
                _ => {
                    error!("Invalid requested domain target level for server bootstrap");
                    debug_assert!(false);
                    return Err(OperationError::MG0009InvalidTargetLevelForBootstrap);
                }
            }

            write_txn
                .internal_apply_domain_migration(domain_target_level)
                .map(|()| {
                    warn!(
                        "Domain level has been bootstrapped to {}",
                        domain_target_level
                    );
                })?;
        }

        // These steps apply both to bootstrapping and normal startup, since we now have
        // a DB with data populated in either path.

        // Domain info is now present, so we need to reflect that in our server
        // domain structures. If we don't do this, the in memory domain level
        // is stuck at 0 which can confuse init domain info below.
        //
        // This also is where the former domain taint flag will be loaded to
        // d_info so that if the *previous* execution of the database was
        // a devel version, we'll still trigger the forced remigration in
        // in the case that we are moving from dev -> stable.
        write_txn.force_domain_reload();

        write_txn.reload()?;

        assert!(write_txn.get_domain_version() > DOMAIN_LEVEL_0);

        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        write_txn.set_phase(ServerPhase::SchemaReady);

        // #2756 - if we *aren't* creating the base IDM entries, then we
        // need to force dyn groups to reload since we're now at schema
        // ready. This is done indirectly by ... reloading the schema again.
        //
        // This is because dyngroups don't load until server phase >= schemaready
        // and the reload path for these is either a change in the dyngroup entry
        // itself or a change to schema reloading. Since we aren't changing the
        // dyngroup here, we have to go via the schema reload path.
        write_txn.force_schema_reload();

        // Reload as init idm affects access controls.
        write_txn.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        write_txn.set_phase(ServerPhase::DomainInfoReady);

        // This is the start of domain info related migrations which we will need in future
        // to handle replication. Due to the access control rework, and the addition of "managed by"
        // syntax, we need to ensure both nodes "fence" replication from each other. We do this
        // by changing domain infos to be incompatible during this phase.

        // The reloads will have populated this structure now.
        let domain_info_version = write_txn.get_domain_version();
        let domain_patch_level = write_txn.get_domain_patch_level();
        let domain_development_taint = write_txn.get_domain_development_taint();
        debug!(
            ?db_domain_version,
            ?domain_patch_level,
            ?domain_development_taint,
            "After setting internal domain info"
        );

        let mut reload_required = false;

        // If the database domain info is a lower version than our target level, we reload.
        if domain_info_version < domain_target_level {
            // if (domain_target_level - domain_info_version) > DOMAIN_MIGRATION_SKIPS {
            if domain_info_version < DOMAIN_MIGRATION_FROM_MIN {
                error!(
                    "UNABLE TO PROCEED. You are attempting a skip update which is NOT SUPPORTED."
                );
                error!(
                    "For more see: https://kubidm.github.io/kubidm/stable/support.html#upgrade-policy and https://kubidm.github.io/kubidm/stable/server_updates.html"
                );
                error!(domain_previous_version = ?domain_info_version, domain_target_version = ?domain_target_level, domain_migration_minimum_limit = ?DOMAIN_MIGRATION_FROM_MIN);
                return Err(OperationError::MG0008SkipUpgradeAttempted);
            }

            // Apply each step in order.
            for domain_target_level_step in domain_info_version..domain_target_level {
                // Rust has no way to do a range with the minimum excluded and the maximum
                // included, so we have to do min -> max which includes min and excludes max,
                // and by adding 1 we gett the same result.
                let domain_target_level_step = domain_target_level_step + 1;

                // Note that this triggers a reload for us, we don't need to manually determine if
                // one is needed or not.
                write_txn
                    .internal_apply_domain_migration(domain_target_level_step)
                    .map(|()| {
                        warn!(
                            "Domain level has been raised to {}",
                            domain_target_level_step
                        );
                    })?;
            }
        } else if domain_info_version > domain_target_level {
            // This is a DOWNGRADE which may not proceed.
            error!("UNABLE TO PROCEED. You are attempting a downgrade which is NOT SUPPORTED.");
            error!(
                "For more see: https://kubidm.github.io/kubidm/stable/support.html#upgrade-policy and https://kubidm.github.io/kubidm/stable/server_updates.html"
            );
            error!(domain_previous_version = ?domain_info_version, domain_target_version = ?domain_target_level);
            return Err(OperationError::MG0010DowngradeNotAllowed);
        } else if domain_development_taint {
            // This forces pre-release versions to re-migrate each start up. This solves
            // the domain-version-sprawl issue so that during a development cycle we can
            // do a single domain version bump, and continue to extend the migrations
            // within that release cycle to contain what we require.
            //
            // If this is a pre-release build
            // AND
            // we are NOT in a test environment
            // AND
            // We did not already need a version migration as above
            write_txn.domain_remigrate(DOMAIN_PREVIOUS_TGT_LEVEL)?;

            reload_required = true;
        }

        // If we are new enough to support patches, and we are lower than the target patch level
        // then a reload will be applied after we raise the patch level.
        if domain_patch_level < DOMAIN_TGT_PATCH_LEVEL {
            write_txn
                .internal_modify_uuid(
                    UUID_DOMAIN_INFO,
                    &ModifyList::new_purge_and_set(
                        Attribute::PatchLevel,
                        Value::new_uint32(DOMAIN_TGT_PATCH_LEVEL),
                    ),
                )
                .map(|()| {
                    warn!(
                        "Domain patch level has been raised to {}",
                        domain_patch_level
                    );
                })?;

            reload_required = true;
        };

        // Execute whatever operations we have batched up and ready to go. This is needed
        // to preserve ordering of the operations - if we reloaded after a remigrate then
        // we would have skipped the patch level fix which needs to have occurred *first*.
        if reload_required {
            write_txn.reload()?;
        }

        // Now set the db/domain devel taint flag to match our current release status
        // if it changes. This is what breaks the cycle of db taint from dev -> stable
        let current_devel_flag = option_env!("KUBIDM_PRE_RELEASE").is_some();
        if current_devel_flag {
            warn!("Domain Development Taint mode is enabled");
        }
        if domain_development_taint != current_devel_flag {
            write_txn.internal_modify_uuid(
                UUID_DOMAIN_INFO,
                &ModifyList::new_purge_and_set(
                    Attribute::DomainDevelopmentTaint,
                    Value::Bool(current_devel_flag),
                ),
            )?;
        }

        // Kubidm: apply any pending reloads while still in the start up phase, where an
        // invalid stored access control profile is skipped rather than failing start up,
        // unless it is a built-in that was valid before the migrations above rewrote it,
        // see `acp_reload_rejects_invalid`. From `Running` on, every profile changed in a
        // transaction is validated strictly.
        write_txn.reload()?;

        // Kubidm: the stored profiles that start up skipped because they are invalid, to
        // report once start up succeeded. This is the only report of them at start up
        // (reloads report newly skipped profiles only once the server is running). A
        // skipped built-in profile is an error: the server is missing access it ships
        // with, until the profile is fixed.
        let (skipped_builtin, skipped_acps) =
            super::acp_skipped_report(&write_txn.get_accesscontrols().get_skipped_profiles());

        // We are ready to run
        write_txn.set_phase(ServerPhase::Running);

        // Commit all changes, this also triggers the final reload, this should be a no-op
        // since we already did all the needed loads above.
        write_txn.commit()?;

        if skipped_builtin {
            error!(
                count = skipped_acps.len(),
                profiles = ?skipped_acps,
                "Some access control profiles, including built-in ones, are invalid and were skipped, they grant nothing until they are fixed or disabled"
            );
            // Kubidm: the re-migration of the current level repairs built-ins (see
            // `kubidm_migrate_builtin_acp_batch`). Pre-release builds run it on every start
            // up; release builds only when the domain level changes.
            if !current_devel_flag {
                error!(
                    "To repair the built-in access control profiles, run `kubidmd domain remigrate` on this server"
                );
            }
        } else if !skipped_acps.is_empty() {
            warn!(
                count = skipped_acps.len(),
                profiles = ?skipped_acps,
                "Some access control profiles are invalid and were skipped, they grant nothing until they are fixed or disabled"
            );
        }

        debug!("Database version check and migrations success! ☀️  ");
        Ok(())
    }
}

impl QueryServerWriteTransaction<'_> {
    /// Apply a domain migration `to_level`. Errors if `to_level` is not greater than or equal to
    /// the active level.
    #[instrument(level = "debug", skip(self))]
    pub(crate) fn internal_apply_domain_migration(
        &mut self,
        to_level: u32,
    ) -> Result<(), OperationError> {
        self.internal_modify_uuid(
            UUID_DOMAIN_INFO,
            &ModifyList::new_purge_and_set(Attribute::Version, Value::new_uint32(to_level)),
        )
        .and_then(|()| self.reload())
    }

    fn internal_migrate_or_create_batch(
        &mut self,
        msg: &str,
        entries: Vec<EntryInitNew>,
    ) -> Result<(), OperationError> {
        let r: Result<(), _> = entries
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if let Err(err) = r {
            error!(?err, msg);
            return Err(err);
        }

        Ok(())
    }

    /// Kubidm: [Self::internal_migrate_or_create_batch] for built-in access control
    /// profiles. Before each profile is rewritten, the values of its stored entry that
    /// the current parser always rejects are removed, see
    /// [Self::kubidm_purge_unsupported_builtin_acp_values]. The generic rewrite keeps
    /// extra stored values, so without this a built-in made invalid by such a value (say,
    /// through replication) would stay skipped, and the values can not be removed in band
    /// (`idm_acp_acp_manage` does not grant them).
    fn kubidm_migrate_builtin_acp_batch(
        &mut self,
        msg: &str,
        entries: Vec<EntryInitNew>,
    ) -> Result<(), OperationError> {
        let r: Result<(), _> = entries.into_iter().try_for_each(|mut entry| {
            migration_data::dl14::kubidm_patch_builtin_acp(&mut entry);
            self.kubidm_purge_unsupported_builtin_acp_values(&entry)
                .and_then(|()| self.internal_migrate_or_create(entry))
        });

        if let Err(err) = r {
            error!(?err, msg);
            return Err(err);
        }

        Ok(())
    }

    /// Kubidm: before the shipped definition `builtin` of a built-in (system uuid range)
    /// access control profile is rewritten over its stored entry, remove from the stored
    /// entry the values (absent from the shipped definition) that would break that rewrite
    /// or the parse of the result. A value the shipped definition has is never removed: a
    /// shipped definition that the parser rejects must still fail loudly. The values are:
    ///
    /// - values that `AccessControlProfile::try_from` and the per kind parsers
    ///   (`access/profiles.rs`) always reject, so they can never be a working
    ///   customisation:
    ///   - `acp_reauth_max_age`, which is unsupported;
    ///   - the `access_control_receiver_delegated` class, which is unsupported, with
    ///     `acp_receiver_delegated`. The class also excludes the group receiver of the
    ///     shipped definition, so the rewrite would otherwise fail;
    ///   - `memberof` and `directmemberof` in `acp_create_attr`, which are server
    ///     maintained (the rewrite also replaces `acp_create_attr` outright when the
    ///     shipped definition has it);
    /// - values that DO parse, and so may be a deliberate administrator customisation, but
    ///   exclude what the shipped definition restores. Removing them reverts that
    ///   customisation to the shipped definition: the shipped values win, and the removal
    ///   is logged at error level so that it is not silent:
    ///   - on a built-in that receives through a group, the
    ///     `access_control_receiver_entry_manager` class (an entry manager receiver),
    ///     which excludes the group receiver;
    ///   - on a built-in that targets a scope, the `access_control_target_delegated_scope`
    ///     class (a delegated target scope), which excludes the target scope;
    /// - with either delegated class removed, the delegated scope, template and grantor
    ///   attributes, unless a delegated class remains (only those classes allow them).
    ///
    /// Any other stored value, valid or not, is left to the upstream rewrite, which keeps
    /// administrator customisations of built-ins that do not conflict with the shipped
    /// definition. The other parser rejections of a built-in (a missing receiver group,
    /// target scope or name, or a target scope that does not validate) are repaired by the
    /// rewrite of the shipped values.
    fn kubidm_purge_unsupported_builtin_acp_values(
        &mut self,
        builtin: &EntryInitNew,
    ) -> Result<(), OperationError> {
        let Some(uuid) = builtin.get_uuid() else {
            return Ok(());
        };
        if uuid >= DYNAMIC_RANGE_MINIMUM_UUID
            || !builtin
                .attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into())
        {
            return Ok(());
        }

        let stored = match self.internal_search_uuid(uuid) {
            Ok(stored) => stored,
            Err(OperationError::NoMatchingEntries) => return Ok(()),
            Err(err) => return Err(err),
        };

        let stored_only = |attr: &Attribute, pv: &PartialValue| {
            stored.attribute_equality(attr, pv) && !builtin.attribute_equality(attr, pv)
        };
        let stored_only_attr =
            |attr: &Attribute| stored.attribute_pres(attr) && !builtin.attribute_pres(attr);
        let has_class = |class: EntryClass| {
            let class = PartialValue::from(class);
            stored.attribute_equality(Attribute::Class, &class)
                || builtin.attribute_equality(Attribute::Class, &class)
        };

        let builtin_has_class = |class: EntryClass| {
            builtin.attribute_equality(Attribute::Class, &PartialValue::from(class))
        };

        let mut mods = Vec::new();
        if stored_only_attr(&Attribute::AcpReauthMaxAge) {
            mods.push(Modify::Purged(Attribute::AcpReauthMaxAge));
        }
        let receiver_delegated = PartialValue::from(EntryClass::AccessControlReceiverDelegated);
        let remove_receiver_delegated = stored_only(&Attribute::Class, &receiver_delegated);
        if remove_receiver_delegated {
            mods.push(Modify::Removed(Attribute::Class, receiver_delegated));
        }
        // An entry manager receiver excludes the group receiver the rewrite restores.
        let receiver_entry_manager =
            PartialValue::from(EntryClass::AccessControlReceiverEntryManager);
        if builtin_has_class(EntryClass::AccessControlReceiverGroup)
            && stored_only(&Attribute::Class, &receiver_entry_manager)
        {
            mods.push(Modify::Removed(Attribute::Class, receiver_entry_manager));
        }
        // A delegated target excludes the target scope the rewrite restores.
        let target_delegated = PartialValue::from(EntryClass::AccessControlTargetDelegatedScope);
        let remove_target_delegated = builtin_has_class(EntryClass::AccessControlTargetScope)
            && stored_only(&Attribute::Class, &target_delegated);
        if remove_target_delegated {
            mods.push(Modify::Removed(Attribute::Class, target_delegated));
        }
        // The delegated scope attributes are only allowed by the two delegated classes:
        // once neither remains, remove them as well.
        let delegated_class_remains = (has_class(EntryClass::AccessControlReceiverDelegated)
            && !remove_receiver_delegated)
            || (has_class(EntryClass::AccessControlTargetDelegatedScope)
                && !remove_target_delegated);
        if (remove_receiver_delegated || remove_target_delegated) && !delegated_class_remains {
            for attr in [
                Attribute::DelegatedScopeGroup,
                Attribute::DelegatedScopeFilter,
                Attribute::DelegatedRoleTemplate,
                Attribute::DelegatedBy,
            ] {
                if stored_only_attr(&attr) {
                    mods.push(Modify::Purged(attr));
                }
            }
        }
        if stored_only_attr(&Attribute::AcpReceiverDelegated) {
            mods.push(Modify::Purged(Attribute::AcpReceiverDelegated));
        }
        for attr in [Attribute::MemberOf, Attribute::DirectMemberOf] {
            let attr = PartialValue::new_iutf8(attr.as_str());
            if stored_only(&Attribute::AcpCreateAttr, &attr) {
                mods.push(Modify::Removed(Attribute::AcpCreateAttr, attr));
            }
        }

        if mods.is_empty() {
            return Ok(());
        }

        error!(
            %uuid,
            name = ?stored.get_ava_single_iname(Attribute::Name),
            ?mods,
            "Removing values that are never valid, or that conflict with the shipped \
             definition (reverting an administrator customisation), from a built-in access \
             control profile"
        );
        self.internal_modify_uuid(uuid, &ModifyList::new_list(mods))
    }

    #[instrument(level = "debug", skip_all)]
    /// - If the thing exists:
    ///   - Ensure the set of attributes match and are present
    ///     (but don't delete multivalue, or extended attributes in the situation.
    /// - If not:
    ///   - Create the entry
    ///
    /// This will extra classes an attributes alone!
    ///
    /// NOTE: `gen_modlist*` IS schema aware and will handle multivalue correctly!
    fn internal_migrate_or_create(
        &mut self,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        // NOTE: Ignoring an attribute only affects the migration phase, not create.
        self.internal_migrate_or_create_ignore_attrs(
            e,
            &[
                // If the credential type is present, we don't want to touch it.
                Attribute::CredentialTypeMinimum,
            ],
        )
    }

    #[instrument(level = "debug", skip_all)]
    fn internal_delete_batch(
        &mut self,
        msg: &str,
        entries: Vec<Uuid>,
    ) -> Result<(), OperationError> {
        let filter = entries
            .into_iter()
            .map(|uuid| f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)))
            .collect();

        // Don't attempt to delete already removed entries that are in the recycle bin.
        let filter = filter!(f_or(filter));

        let result = self.internal_delete(&filter);

        match result {
            Ok(_) | Err(OperationError::NoMatchingEntries) => Ok(()),
            Err(err) => {
                error!(?err, msg);
                Err(err)
            }
        }
    }

    /// This is the same as [QueryServerWriteTransaction::internal_migrate_or_create]
    /// but it will ignore the specified list of attributes, so that if an admin has
    /// modified those values then we don't stomp them.
    #[instrument(level = "trace", skip_all)]
    fn internal_migrate_or_create_ignore_attrs(
        &mut self,
        mut e: Entry<EntryInit, EntryNew>,
        attrs: &[Attribute],
    ) -> Result<(), OperationError> {
        debug!("operating on {:?}", e.get_display_id());
        trace!(?e, ?attrs);

        let Some(filt) = e.filter_from_attrs(&[Attribute::Uuid]) else {
            return Err(OperationError::FilterGeneration);
        };

        trace!("search {:?}", filt);

        let results = self.internal_search(filt.clone())?;

        if results.is_empty() {
            // The entry does not exist. Create it.

            // If there are create-once members, set them up now.
            if let Some(members_create_once) = e.pop_ava(Attribute::MemberCreateOnce) {
                if let Some(members) = e.get_ava_mut(Attribute::Member) {
                    // Merge
                    members.merge(&members_create_once).inspect_err(|err| {
                        error!(?err, "Unable to merge member sets, mismatched types?");
                    })?;
                } else {
                    // Just push
                    e.set_ava_set(&Attribute::Member, members_create_once);
                }
            };

            self.internal_create(vec![e])
        } else if results.len() == 1 {
            // This is always ignored during migration.
            e.remove_ava(&Attribute::MemberCreateOnce);

            // For each ignored attr, we remove it from entry.
            for attr in attrs.iter() {
                e.remove_ava(attr);
            }

            // If the thing is subset, pass
            match e.gen_modlist_assert(&self.schema) {
                Ok(modlist) => {
                    // Apply to &results[0]
                    trace!(?modlist);
                    self.internal_modify(&filt, &modlist)
                }
                Err(e) => Err(OperationError::SchemaViolation(e)),
            }
        } else {
            admin_error!(
                "Invalid Result Set - Expected One Entry for {:?} - {:?}",
                filt,
                results
            );
            Err(OperationError::InvalidDbState)
        }
    }

    // Commented as an example of patch application
    /*
    /// Patch Application - This triggers a one-shot fixup task for issue #3178
    /// to force access controls to re-migrate in existing databases so that they're
    /// content matches expected values.
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_patch_level_2(&mut self) -> Result<(), OperationError> {
        admin_warn!("applying domain patch 2.");

        debug_assert!(*self.phase >= ServerPhase::SchemaReady);

        let idm_data = migration_data::dl9::phase_7_builtin_access_control_profiles();

        idm_data
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_patch_level_2 -> Error");
                err
            })?;

        self.reload()?;

        Ok(())
    }
    */

    /// Migration domain level 10 to 11 (1.7.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_10_to_11(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_10 {
            error!("Unable to raise domain level from 10 to 11.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl11::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl11::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl11::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl11::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl11::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl11::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl11::phase_7_builtin_access_control_profiles(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Migration domain level 11 to 12 (1.8.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_11_to_12(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_11 {
            error!("Unable to raise domain level from 11 to 12.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl12::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl12::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl12::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl12::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl12::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl12::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl12::phase_7_builtin_access_control_profiles(),
        )?;

        self.reload()?;

        // Cleanup any leftover id keys
        let modlist = ModifyList::new_purge(Attribute::IdVerificationEcKey);
        let filter = filter_all!(f_pres(Attribute::IdVerificationEcKey));

        self.internal_modify(&filter, &modlist)?;

        Ok(())
    }

    /// Migration domain level 12 to 13 (1.9.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_12_to_13(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_12 {
            error!("Unable to raise domain level from 12 to 13.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl13::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl13::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl13::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl13::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl13::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl13::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl13::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDS",
            migration_data::dl13::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Migration domain level 13 to 14 (1.10.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_13_to_14(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_13 {
            error!("Unable to raise domain level from 13 to 14.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl14::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl14::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl14::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl14 system entries",
            migration_data::dl14::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl14::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl14::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl14::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDS",
            migration_data::dl14::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        // Default PasswordChangedTime to UNIX_EPOCH
        let filter = filter_all!(f_and!([
            f_eq(Attribute::Class, EntryClass::Person.into()),
            f_andnot(f_pres(Attribute::PasswordChangedTime)),
        ]));
        let modlist = ModifyList::new_purge_and_set(
            Attribute::PasswordChangedTime,
            Value::DateTime(time::OffsetDateTime::UNIX_EPOCH),
        );
        self.internal_modify(&filter, &modlist)?;

        Ok(())
    }

    pub(crate) fn migrate_schema_1_11(&mut self) -> Result<(), OperationError> {
        // Flag that the schema changes - this is important because now that the
        // schema is in memory only, the on-disk triggers won't fire now.
        self.force_schema_reload();

        let mut all_attrs = migration_data::dl15::phase_1_schema_attrs();
        let mut all_classes = migration_data::dl15::phase_2_schema_classes();

        // Kubidm fork-only schema (delegation, step-up reauth, ACP time restrictions,
        // time-bounded grants, OAuth2 federation, approvals). Chained last so the fork's
        // overrides win.
        all_attrs.extend(crate::schema::kubidm_schema_attributes());
        all_classes.extend(crate::schema::kubidm_schema_classes());

        self.schema.extend_in_memory(all_attrs, all_classes)
    }

    /// Migration domain level 14 to 15 (1.11.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_1_10_to_1_11(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_14 {
            error!(
                "Unable to raise domain level from {} to {}.",
                DOMAIN_LEVEL_14, DOMAIN_LEVEL_1_11
            );
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.migrate_schema_1_11()?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        self.delete_db_stored_schema()?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl15::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl15 system entries",
            migration_data::dl15::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl15::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl15::phase_6_builtin_non_admin_entries()?,
        )?;

        // Kubidm fork builtin entries (delegated roles, approval admins group). The
        // upstream entry lists for this level do not contain them.
        //
        // Kubidm: this domain migration is the only place that creates them (and the
        // idm_high_privilege membership) in an existing database. That is enough because no
        // released fork version targets DL 1.12 (released databases reach it through the
        // 1.11 -> 1.12 migration), and pre-release builds re-run the migrations of the
        // current level on every start (development taint). Once a release targets 1.12,
        // fork builtins added later need a migration of their own.
        self.internal_migrate_or_create_batch(
            "phase 6 - kubidm builtin entries",
            migration_data::dl14::kubidm_builtin_entries()?,
        )?;

        self.kubidm_migrate_builtin_acp_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl15::phase_7_builtin_access_control_profiles(),
        )?;

        self.kubidm_migrate_builtin_acp_batch(
            "phase 7 - kubidm builtin access control profiles",
            migration_data::dl14::kubidm_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDS",
            migration_data::dl15::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        // Default PasswordChangedTime to UNIX_EPOCH
        let filter = filter_all!(f_and!([
            f_eq(Attribute::Class, EntryClass::Person.into()),
            f_andnot(f_pres(Attribute::PasswordChangedTime)),
        ]));
        let modlist = ModifyList::new_purge_and_set(
            Attribute::PasswordChangedTime,
            Value::DateTime(time::OffsetDateTime::UNIX_EPOCH),
        );
        self.internal_modify(&filter, &modlist)?;

        Ok(())
    }

    /// Delete every `attributetype` and `classtype` entry stored in the database.
    ///
    /// From 1.11 the schema lives in memory and `reload_schema` never reads these
    /// entries, so they are inert. A fresh 1.11+ database has none, and removing
    /// them makes upgraded databases match. This includes custom schema created
    /// before 1.11, which is equally ignored from 1.11 onwards.
    ///
    /// 1.11.x releases matched these with `f_and` (no entry carries both classes),
    /// so they were never removed there. The 1.11 -> 1.12 migration calls this
    /// again to clean up databases upgraded by those releases.
    fn delete_db_stored_schema(&mut self) -> Result<(), OperationError> {
        let filter = filter!(f_or(vec![
            f_eq(Attribute::Class, EntryClass::ClassType.into()),
            f_eq(Attribute::Class, EntryClass::AttributeType.into()),
        ]));

        self.internal_delete_if_exists(&filter)
    }

    pub(crate) fn migrate_schema_1_12(&mut self) -> Result<(), OperationError> {
        // Flag that the schema changes - this is important because now that the
        // schema is in memory only, the on-disk triggers won't fire now.
        self.force_schema_reload();

        let mut all_attrs = migration_data::dl_1_12::phase_1_schema_attrs();
        let mut all_classes = migration_data::dl_1_12::phase_2_schema_classes();

        // Kubidm fork-only schema (delegation, step-up reauth, ACP time restrictions,
        // time-bounded grants, OAuth2 federation, approvals). Chained last so the fork's
        // overrides win.
        all_attrs.extend(crate::schema::kubidm_schema_attributes());
        all_classes.extend(crate::schema::kubidm_schema_classes());

        self.schema.extend_in_memory(all_attrs, all_classes)
    }

    /// Migration domain level 1.11 to 1.12
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_1_11_to_1_12(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_1_12 {
            error!("Unable to raise domain level from 1_11 to 1_12.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        use migration_data::dl_1_12 as dl_target;

        if self.get_phase() >= ServerPhase::DomainInfoReady {
            // Rewrite all entries in place to cause them to re-write their on disk format.
            let filter = filter_all!(f_or!([
                // Uuid
                f_pres(Attribute::DomainUuid),
                f_pres(Attribute::InMemoriam),
                f_pres(Attribute::OAuth2AccountCredentialUuid),
                f_pres(Attribute::Uuid),
                f_pres(Attribute::CascadeDeleted),
                // Refer
                f_pres(Attribute::KeyProvider),
                f_pres(Attribute::LinkedGroup),
                f_pres(Attribute::SyncParentUuid),
                f_pres(Attribute::Refers),
                f_pres(Attribute::OAuth2AccountProvider),
                f_pres(Attribute::EntryManagedBy),
                // kubidm refer
                f_pres(Attribute::AcpReceiverDelegated),
                f_pres(Attribute::DelegatedScopeGroup),
                f_pres(Attribute::DelegatedBy),
                f_pres(Attribute::DelegatedRoleTemplate),
                // kubidm single value Url / Iutf8 / Iname (OAuth2 federation, DL14)
                f_pres(Attribute::OAuth2Issuer),
                f_pres(Attribute::OAuth2JwksUri),
                f_pres(Attribute::OAuth2UserinfoEndpoint),
                f_pres(Attribute::OAuth2LinkPolicy),
                f_pres(Attribute::OAuth2FederationId),
                // Iutf8
                f_pres(Attribute::LoginShell),
                f_pres(Attribute::DomainLdapBasedn),
                f_pres(Attribute::AttributeName),
                f_pres(Attribute::ClassName),
                f_pres(Attribute::SyncExternalId),
                // Iname
                f_pres(Attribute::DomainName),
                f_pres(Attribute::OAuth2RsName),
                f_pres(Attribute::Name),
                // Url
                f_pres(Attribute::ApplicationUrl),
                f_pres(Attribute::OAuth2RsOriginLanding),
                f_pres(Attribute::OAuth2TokenEndpoint),
                f_pres(Attribute::SyncCredentialPortal),
                f_pres(Attribute::OAuth2AuthorisationEndpoint),
                f_pres(Attribute::OAuth2TokenIntrospectEndpoint),
            ]));

            let mut entries = self.internal_search_writeable(&filter)?;

            // Migrate the formerly multivalue types to single value types.
            for (_, entry) in entries.iter_mut() {
                for attr in [
                    // Uuid
                    Attribute::DomainUuid,
                    Attribute::InMemoriam,
                    Attribute::OAuth2AccountCredentialUuid,
                    Attribute::Uuid,
                    Attribute::CascadeDeleted,
                    // Refer
                    Attribute::KeyProvider,
                    Attribute::LinkedGroup,
                    Attribute::SyncParentUuid,
                    Attribute::Refers,
                    Attribute::OAuth2AccountProvider,
                    Attribute::EntryManagedBy,
                    // kubidm refer
                    Attribute::AcpReceiverDelegated,
                    Attribute::DelegatedScopeGroup,
                    Attribute::DelegatedBy,
                    Attribute::DelegatedRoleTemplate,
                    // kubidm single value Url / Iutf8 / Iname (OAuth2 federation, DL14)
                    Attribute::OAuth2Issuer,
                    Attribute::OAuth2JwksUri,
                    Attribute::OAuth2UserinfoEndpoint,
                    Attribute::OAuth2LinkPolicy,
                    Attribute::OAuth2FederationId,
                    // Iutf8
                    Attribute::LoginShell,
                    Attribute::DomainLdapBasedn,
                    Attribute::AttributeName,
                    Attribute::ClassName,
                    Attribute::SyncExternalId,
                    // Iname
                    Attribute::DomainName,
                    Attribute::OAuth2RsName,
                    Attribute::Name,
                    // Url
                    Attribute::ApplicationUrl,
                    Attribute::OAuth2RsOriginLanding,
                    Attribute::OAuth2TokenEndpoint,
                    Attribute::SyncCredentialPortal,
                    Attribute::OAuth2AuthorisationEndpoint,
                    Attribute::OAuth2TokenIntrospectEndpoint,
                ] {
                    entry.migrate_ava(attr)?;
                }
            }

            let count = entries.len();

            self.internal_apply_writable(entries)?;

            debug!("Updated DB format for {} entries", count);
        }

        // =========== Apply changes ==============
        self.migrate_schema_1_12()?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        self.delete_db_stored_schema()?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            dl_target::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            dl_target::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            dl_target::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            dl_target::phase_6_builtin_non_admin_entries()?,
        )?;

        // Kubidm fork builtin entries (delegated roles, approval admins group). The
        // upstream entry lists for this level do not contain them.
        //
        // Kubidm: this domain migration is the only place that creates them (and the
        // idm_high_privilege membership) in an existing database. That is enough because no
        // released fork version targets DL 1.12 (released databases reach it through the
        // 1.11 -> 1.12 migration), and pre-release builds re-run the migrations of the
        // current level on every start (development taint). Once a release targets 1.12,
        // fork builtins added later need a migration of their own.
        self.internal_migrate_or_create_batch(
            "phase 6 - kubidm builtin entries",
            migration_data::dl14::kubidm_builtin_entries()?,
        )?;

        self.kubidm_migrate_builtin_acp_batch(
            "phase 7 - builtin access control profiles",
            dl_target::phase_7_builtin_access_control_profiles(),
        )?;

        self.kubidm_migrate_builtin_acp_batch(
            "phase 7 - kubidm builtin access control profiles",
            migration_data::dl14::kubidm_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch("phase 8 - delete UUIDS", dl_target::phase_8_delete_uuids())?;

        self.reload()?;

        let filter = filter_all!(f_and!([f_eq(
            Attribute::Class,
            EntryClass::OAuth2ResourceServer.into()
        ),]));
        let modlist =
            ModifyList::new_append(Attribute::Class, EntryClass::KeyObjectJweA256GCM.into());
        self.internal_modify(&filter, &modlist)?;

        Ok(())
    }

    /// Migration domain level 1.12 to 1.13
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_1_12_to_1_13(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_1_13 {
            error!("Unable to raise domain level from 1_12 to 1_13.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn initialise_schema_core(&mut self) -> Result<(), OperationError> {
        debug!("initialise_schema_core -> start ...");
        // Load in all the "core" schema, that we already have in "memory".
        let entries = self.schema.to_entries();

        // admin_debug!("Dumping schemas: {:?}", entries);

        // internal_migrate_or_create.
        let r: Result<_, _> = entries.into_iter().try_for_each(|e| {
            trace!(?e, "init schema entry");
            self.internal_migrate_or_create(e)
        });
        if r.is_ok() {
            debug!("initialise_schema_core -> Ok!");
        } else {
            error!(?r, "initialise_schema_core -> Error");
        }
        // why do we have error handling if it's always supposed to be `Ok`?
        debug_assert!(r.is_ok());
        r
    }
}

impl QueryServerReadTransaction<'_> {
    /// Retrieve the domain info of this server
    pub fn domain_upgrade_check(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckReport, OperationError> {
        let d_info = &self.d_info;

        let name = d_info.d_name.clone();
        let uuid = d_info.d_uuid;
        let current_level = d_info.d_vers;
        let upgrade_level = DOMAIN_TGT_NEXT_LEVEL;

        let report_items = Vec::with_capacity(1);

        // Intentionally left commented to serve as a future check template.
        /*
        if current_level <= DOMAIN_LEVEL_7 && upgrade_level >= DOMAIN_LEVEL_8 {
            let item = self
                .domain_upgrade_check_7_to_8_oauth2_strict_redirect_uri()
                .map_err(|err| {
                    error!(
                        ?err,
                        "Failed to perform domain upgrade check 7 to 8 - oauth2-strict-redirect_uri"
                    );
                    err
                })?;
            report_items.push(item);
        }
        */

        Ok(ProtoDomainUpgradeCheckReport {
            name,
            uuid,
            current_level,
            upgrade_level,
            report_items,
        })
    }

    // Intentionally left commented to serve as a future check template.
    /*
    pub(crate) fn domain_upgrade_check_7_to_8_oauth2_strict_redirect_uri(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckItem, OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
            f_andnot(f_pres(Attribute::OAuth2StrictRedirectUri)),
        ]));

        let results = self.internal_search(filter)?;

        let affected_entries = results
            .into_iter()
            .map(|entry| entry.get_display_id())
            .collect::<Vec<_>>();

        let status = if affected_entries.is_empty() {
            ProtoDomainUpgradeCheckStatus::Pass7To8Oauth2StrictRedirectUri
        } else {
            ProtoDomainUpgradeCheckStatus::Fail7To8Oauth2StrictRedirectUri
        };

        Ok(ProtoDomainUpgradeCheckItem {
            status,
            from_level: DOMAIN_LEVEL_7,
            to_level: DOMAIN_LEVEL_8,
            affected_entries,
        })
    }
    */
}

#[cfg(test)]
mod tests {
    // use super::{ProtoDomainUpgradeCheckItem, ProtoDomainUpgradeCheckStatus};
    use std::collections::BTreeSet;

    use crate::{prelude::*, value::CredentialType, valueset::ValueSetCredentialType};

    /// A migration error must fail startup in release builds as well as debug builds.
    /// In particular, a failed ACP patch must never be mistaken for a completed upgrade.
    #[qs_test]
    async fn test_migration_batch_failures_propagate(server: &QueryServer) {
        let mut txn = server.write(duration_from_epoch_now()).await.unwrap();
        assert_eq!(
            txn.internal_migrate_or_create_batch("invalid generic entry", vec![EntryInitNew::new()]),
            Err(OperationError::FilterGeneration)
        );
        assert_eq!(
            txn.kubidm_migrate_builtin_acp_batch("invalid ACP entry", vec![EntryInitNew::new()]),
            Err(OperationError::FilterGeneration)
        );
    }

    /// Kubidm guard: the fork-only builtin entries (delegated roles, approval admins, the
    /// high privilege membership) are not part of the upstream phase 6 lists, so every
    /// domain level migration has to chain `kubidm_builtin_entries`. After a bootstrap at
    /// `DOMAIN_TGT_LEVEL` every one of them must exist.
    #[qs_test]
    async fn test_migrations_kubidm_builtin_entries_exist(server: &QueryServer) {
        let mut read_txn = server
            .read()
            .await
            .expect("Failed to start read transaction");

        let entries = crate::migration_data::dl14::kubidm_builtin_entries()
            .expect("failed to build the kubidm builtin entries");
        assert!(!entries.is_empty());

        let mut missing = Vec::new();
        for entry in entries {
            let uuid = entry.get_uuid().expect("builtin entry without a uuid");
            if !read_txn
                .internal_exists_uuid(uuid)
                .expect("failed to search for a builtin entry")
            {
                missing.push(uuid);
            }
        }

        assert!(
            missing.is_empty(),
            "kubidm builtin entries missing at DOMAIN_TGT_LEVEL ({DOMAIN_TGT_LEVEL}): {missing:?}"
        );

        // `idm_high_privilege` exists upstream, so the existence check above passes even
        // when the fork's partial membership entry was never applied. Check the member.
        let high_privilege = read_txn
            .internal_search_uuid(UUID_IDM_HIGH_PRIVILEGE)
            .expect("idm_high_privilege missing");
        assert!(
            high_privilege.attribute_equality(
                Attribute::Member,
                &PartialValue::Refer(UUID_IDM_APPROVAL_ADMINS)
            ),
            "idm_high_privilege does not have idm_approval_admins as a member"
        );
    }

    /// Kubidm: the migrations rewrite the built-in access control profiles in the start up
    /// transaction, which marks them changed, so a rewrite that leaves a valid built-in
    /// invalid (a shipped definition or parser bug) fails strictly, even before the server
    /// is `Running`. A stored built-in that was already invalid before the rewrite (say,
    /// from replication) is skipped instead, through the rewrite too, so the node starts.
    #[qs_test]
    async fn test_migrations_builtin_acp_rewrite_strict(server: &QueryServer) {
        use crate::server::{ChangeFlag, ServerPhase};

        let ct = duration_from_epoch_now();
        let builtin = || {
            crate::migration_data::latest::phase_7_builtin_access_control_profiles()
                .into_iter()
                .find(|entry| entry.get_uuid() == Some(UUID_IDM_ACP_PEOPLE_READ_V1))
                .expect("builtin acp")
        };
        let mut invalid_builtin = builtin();
        invalid_builtin.add_ava(Attribute::AcpReauthMaxAge, Value::Uint32(300));
        let is_skipped = |write_txn: &QueryServerWriteTransaction<'_>| {
            write_txn
                .get_accesscontrols()
                .get_skipped_profiles()
                .contains_key(&UUID_IDM_ACP_PEOPLE_READ_V1)
        };

        // Mid migration (before `Running`), the phase 7 rewrite of a valid built-in with
        // invalid content is refused.
        let mut write_txn = server.write(ct).await.unwrap();
        write_txn.set_phase_bootstrap();
        write_txn.set_phase(ServerPhase::SchemaReady);
        write_txn
            .internal_migrate_or_create(invalid_builtin)
            .expect("migrate");
        assert!(write_txn.is_changed_uuid(&UUID_IDM_ACP_PEOPLE_READ_V1));
        assert_eq!(
            write_txn.reload(),
            Err(OperationError::InvalidAcpState(format!(
                "{} is unsupported",
                Attribute::AcpReauthMaxAge
            )))
        );
        drop(write_txn);

        // Stored invalid content (from replication) ...
        let mut write_txn = server.write(ct).await.unwrap();
        write_txn.replication_apply = true;
        write_txn
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_READ_V1,
                &ModifyList::new_purge_and_set(Attribute::AcpReauthMaxAge, Value::Uint32(300)),
            )
            .expect("modify");
        write_txn.commit().expect("commit");

        // ... is skipped by a mid migration reload before the rewrite, and by the reload
        // after the generic rewrite, which keeps the extra attribute (the built-in
        // profile migrations remove it, see
        // `test_migrations_builtin_acp_unsupported_values_repaired`).
        let mut write_txn = server.write(ct).await.unwrap();
        write_txn.set_phase_bootstrap();
        write_txn.set_phase(ServerPhase::SchemaReady);
        write_txn.changed_flags.insert(ChangeFlag::ACP);
        write_txn.reload().expect("reload");
        assert!(is_skipped(&write_txn));
        write_txn
            .internal_migrate_or_create(builtin())
            .expect("migrate");
        assert!(write_txn.is_changed_uuid(&UUID_IDM_ACP_PEOPLE_READ_V1));
        write_txn.reload().expect("reload");
        assert!(is_skipped(&write_txn));
        drop(write_txn);

        // A start up succeeds. A pre-release build re-runs the migrations of the current
        // level on every start up, and the built-in profile migrations repair the
        // built-in. Otherwise it stays skipped.
        let mut write_txn = server.write(ct).await.unwrap();
        write_txn.set_phase_bootstrap();
        write_txn.commit().expect("commit");
        server
            .initialise_helper(ct, DOMAIN_TGT_LEVEL)
            .await
            .expect("start up");
        let write_txn = server.write(ct).await.unwrap();
        assert_eq!(
            is_skipped(&write_txn),
            option_env!("KUBIDM_PRE_RELEASE").is_none()
        );
    }

    /// Kubidm: a built-in access control profile made invalid by values that the parser
    /// always rejects (here through replication, which is lenient) is skipped, and can not
    /// be repaired in band. The built-in profile migrations remove those values when they
    /// rewrite it, so a (re)migration loads it again, while other customisations of the
    /// built-in are kept.
    #[qs_test]
    async fn test_migrations_builtin_acp_unsupported_values_repaired(server: &QueryServer) {
        use crate::server::ServerPhase;

        let ct = duration_from_epoch_now();
        let iutf8 = |attr: Attribute| Value::new_iutf8n(attr.as_str());
        let builtins = [
            UUID_IDM_ACP_PEOPLE_READ_V1,
            UUID_IDM_ACP_PEOPLE_CREATE_V1,
            UUID_IDM_ACP_PEOPLE_MANAGE_V1,
        ];

        let mut write_txn = server.write(ct).await.unwrap();
        write_txn.replication_apply = true;
        // An unsupported step-up maximum age, and a valid time restriction.
        write_txn
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_READ_V1,
                &ModifyList::new_list(vec![
                    Modify::Present(Attribute::AcpReauthMaxAge, Value::Uint32(300)),
                    Modify::Present(
                        Attribute::AcpTimeRestrictionEnd,
                        Value::DateTime(
                            time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(36500),
                        ),
                    ),
                ]),
            )
            .expect("modify");
        // The server maintained memberof granted on create.
        write_txn
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_CREATE_V1,
                &ModifyList::new_list(vec![
                    Modify::Present(Attribute::AcpCreateAttr, iutf8(Attribute::MemberOf)),
                    Modify::Present(Attribute::AcpCreateAttr, iutf8(Attribute::DirectMemberOf)),
                ]),
            )
            .expect("modify");
        // An unsupported delegated receiver, instead of the group receiver.
        write_txn
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_MANAGE_V1,
                &ModifyList::new_list(vec![
                    Modify::Removed(
                        Attribute::Class,
                        EntryClass::AccessControlReceiverGroup.into(),
                    ),
                    Modify::Purged(Attribute::AcpReceiverGroup),
                    Modify::Present(
                        Attribute::Class,
                        EntryClass::AccessControlReceiverDelegated.to_value(),
                    ),
                    Modify::Present(
                        Attribute::AcpReceiverDelegated,
                        Value::Refer(UUID_IDM_ADMINS),
                    ),
                ]),
            )
            .expect("modify");
        // An entry manager receiver instead of the group receiver, and a delegated target
        // instead of the target scope. Both parse, but exclude the receiver and target
        // that the rewrite restores, so the rewrite would fail.
        write_txn
            .internal_modify_uuid(
                UUID_IDM_ACP_GROUP_MANAGE_V1,
                &ModifyList::new_list(vec![
                    Modify::Removed(
                        Attribute::Class,
                        EntryClass::AccessControlReceiverGroup.into(),
                    ),
                    Modify::Purged(Attribute::AcpReceiverGroup),
                    Modify::Present(
                        Attribute::Class,
                        EntryClass::AccessControlReceiverEntryManager.to_value(),
                    ),
                ]),
            )
            .expect("modify");
        write_txn
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_DELETE_V1,
                &ModifyList::new_list(vec![
                    Modify::Removed(
                        Attribute::Class,
                        EntryClass::AccessControlTargetScope.into(),
                    ),
                    Modify::Purged(Attribute::AcpTargetScope),
                    Modify::Present(
                        Attribute::Class,
                        EntryClass::AccessControlTargetDelegatedScope.to_value(),
                    ),
                    Modify::Present(
                        Attribute::DelegatedScopeGroup,
                        Value::Refer(UUID_IDM_PEOPLE_ADMINS),
                    ),
                    // A delegated target parses only with a known template.
                    Modify::Present(
                        Attribute::DelegatedRoleTemplate,
                        Value::Refer(UUID_IDM_DELEGATED_USER_ADMIN),
                    ),
                    Modify::Present(
                        Attribute::DelegatedScopeFilter,
                        Value::JsonFilt(ProtoFilter::Eq(
                            Attribute::Class.to_string(),
                            EntryClass::Person.to_string(),
                        )),
                    ),
                ]),
            )
            .expect("modify");
        write_txn.commit().expect("commit");

        // They are skipped.
        let write_txn = server.write(ct).await.unwrap();
        let skipped: BTreeSet<Uuid> = write_txn
            .get_accesscontrols()
            .get_skipped_profiles()
            .into_keys()
            .collect();
        assert_eq!(skipped, BTreeSet::from(builtins));
        drop(write_txn);

        // A re-migration of the current level, as a pre-release build runs on start up,
        // removes the unsupported values and loads them again.
        let mut write_txn = server.write(ct).await.unwrap();
        write_txn.set_phase_bootstrap();
        write_txn.set_phase(ServerPhase::DomainInfoReady);
        write_txn
            .domain_remigrate(DOMAIN_PREVIOUS_TGT_LEVEL)
            .expect("remigrate");
        write_txn.reload().expect("re-migrate");
        write_txn.set_phase(ServerPhase::Running);
        write_txn.commit().expect("commit");

        let mut write_txn = server.write(ct).await.unwrap();
        crate::server::access::assert_builtin_acps_all_loaded(&mut write_txn);

        let read = write_txn
            .internal_search_uuid(UUID_IDM_ACP_PEOPLE_READ_V1)
            .expect("acp");
        assert!(!read.attribute_pres(Attribute::AcpReauthMaxAge));
        assert!(read.attribute_pres(Attribute::AcpTimeRestrictionEnd));

        let create = write_txn
            .internal_search_uuid(UUID_IDM_ACP_PEOPLE_CREATE_V1)
            .expect("acp");
        let create_attrs: BTreeSet<&str> = create
            .get_ava_iter_iutf8(Attribute::AcpCreateAttr)
            .expect("create attrs")
            .collect();
        assert!(!create_attrs.contains(Attribute::MemberOf.as_str()));
        assert!(!create_attrs.contains(Attribute::DirectMemberOf.as_str()));
        assert!(create_attrs.contains(Attribute::DisplayName.as_str()));

        let manage = write_txn
            .internal_search_uuid(UUID_IDM_ACP_PEOPLE_MANAGE_V1)
            .expect("acp");
        assert!(!manage.attribute_equality(
            Attribute::Class,
            &EntryClass::AccessControlReceiverDelegated.into()
        ));
        assert!(!manage.attribute_pres(Attribute::AcpReceiverDelegated));
        assert!(manage.attribute_equality(
            Attribute::AcpReceiverGroup,
            &PartialValue::Refer(UUID_IDM_PEOPLE_ADMINS)
        ));

        let group_manage = write_txn
            .internal_search_uuid(UUID_IDM_ACP_GROUP_MANAGE_V1)
            .expect("acp");
        assert!(!group_manage.attribute_equality(
            Attribute::Class,
            &EntryClass::AccessControlReceiverEntryManager.into()
        ));
        assert!(group_manage.attribute_equality(
            Attribute::Class,
            &EntryClass::AccessControlReceiverGroup.into()
        ));
        assert!(group_manage.attribute_equality(
            Attribute::AcpReceiverGroup,
            &PartialValue::Refer(UUID_IDM_GROUP_ADMINS)
        ));

        let people_delete = write_txn
            .internal_search_uuid(UUID_IDM_ACP_PEOPLE_DELETE_V1)
            .expect("acp");
        assert!(!people_delete.attribute_equality(
            Attribute::Class,
            &EntryClass::AccessControlTargetDelegatedScope.into()
        ));
        assert!(!people_delete.attribute_pres(Attribute::DelegatedScopeGroup));
        assert!(!people_delete.attribute_pres(Attribute::DelegatedScopeFilter));
        assert!(!people_delete.attribute_pres(Attribute::DelegatedRoleTemplate));
        assert!(people_delete.attribute_equality(
            Attribute::Class,
            &EntryClass::AccessControlTargetScope.into()
        ));
        assert!(people_delete.attribute_pres(Attribute::AcpTargetScope));
    }

    #[qs_test]
    async fn test_init_idempotent_schema_core(server: &QueryServer) {
        {
            // Setup and abort.
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
        {
            // Now do it again in a new txn, but abort
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            // Now do it again in a new txn.
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
    }

    /// This test is for ongoing/longterm checks over the previous to current version.
    /// This is in contrast to the specific version checks below that are often to
    /// test a version to version migration.
    #[qs_test(domain_level=DOMAIN_PREVIOUS_TGT_LEVEL)]
    async fn test_migrations_dl_previous_to_dl_target(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_PREVIOUS_TGT_LEVEL);

        // == SETUP ==

        // Add a member to a group - it should not be removed.
        // Remove a default member from a group - it should be returned.
        let modlist = ModifyList::new_set(
            Attribute::Member,
            // This achieves both because this removes IDM_ADMIN from the group
            // while setting only anon as a member.
            ValueSetReferN::new(UUID_ANONYMOUS),
        );
        write_txn
            .internal_modify_uuid(UUID_IDM_ADMINS, &modlist)
            .expect("Unable to modify CredentialTypeMinimum");

        // Remove a group from an object that is "create once".  It should not
        // be re-added.
        let modlist = ModifyList::new_purge(Attribute::Member);
        write_txn
            .internal_modify_uuid(UUID_IDM_PEOPLE_SELF_NAME_WRITE, &modlist)
            .expect("Unable to remove idm_all_persons from self-write");

        // Change default account policy - it should not be reverted.
        let modlist = ModifyList::new_set(
            Attribute::CredentialTypeMinimum,
            ValueSetCredentialType::new(CredentialType::Any),
        );
        write_txn
            .internal_modify_uuid(UUID_IDM_ALL_PERSONS, &modlist)
            .expect("Unable to modify CredentialTypeMinimum");

        write_txn.commit().expect("Unable to commit");

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_TGT_LEVEL)
            .expect("Unable to set domain level");

        // post migration verification.
        // Check that our group is as we left it
        let idm_admins_entry = write_txn
            .internal_search_uuid(UUID_IDM_ADMINS)
            .expect("Unable to retrieve all persons");

        debug!(?idm_admins_entry);

        let members = idm_admins_entry
            .get_ava_refer(Attribute::Member)
            .expect("No members present");

        // Still present
        assert!(members.contains(&UUID_ANONYMOUS));
        // Was reverted
        assert!(members.contains(&UUID_IDM_ADMIN));

        // Check that self-write still doesn't have all persons.
        let idm_people_self_name_write_entry = write_txn
            .internal_search_uuid(UUID_IDM_PEOPLE_SELF_NAME_WRITE)
            .expect("Unable to retrieve all persons");

        let members = idm_people_self_name_write_entry.get_ava_refer(Attribute::Member);

        // There are no members!
        assert!(members.is_none());

        // Check that the account policy did not revert.
        let all_persons_entry = write_txn
            .internal_search_uuid(UUID_IDM_ALL_PERSONS)
            .expect("Unable to retrieve all persons");

        assert_eq!(
            all_persons_entry.get_ava_single_credential_type(Attribute::CredentialTypeMinimum),
            Some(CredentialType::Any)
        );

        // Kubidm: nothing is skipped, every built-in access control profile is loaded.
        crate::server::access::assert_builtin_acps_all_loaded(&mut write_txn);

        write_txn.commit().expect("Unable to commit");
    }

    /// Kubidm: fork schema and builtin entries survive the previous -> target domain
    /// migration. The 1.11 -> 1.12 on-disk rewrite filters on fork attributes, which must
    /// therefore exist in the 1.11 schema, and the fork builtin entries are created by the
    /// migration although they are not in the upstream entry lists.
    #[qs_test(domain_level=DOMAIN_PREVIOUS_TGT_LEVEL)]
    async fn test_migrations_dl_previous_to_dl_target_kubidm(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let fed_uuid = Uuid::new_v4();
        write_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::OAuth2Federation.to_value()),
                (Attribute::Uuid, Value::Uuid(fed_uuid)),
                (Attribute::Name, Value::new_iname("migrated_federation")),
                (Attribute::OAuth2ClientId, Value::new_utf8s("client_id")),
                (Attribute::OAuth2ClientSecret, Value::new_utf8s("secret")),
                (
                    Attribute::OAuth2Issuer,
                    Value::Url(Url::parse("https://idp.example.com").unwrap())
                ),
                (Attribute::OAuth2LinkPolicy, Value::new_iutf8("manual")),
                (
                    Attribute::OAuth2FederationId,
                    Value::new_iname("migrated_fed")
                )
            )])
            .expect("oauth2 federation must be valid at the previous domain level");
        write_txn.commit().expect("Unable to commit");

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // idm_approval_admins is high privilege at the previous level too. Remove that to
        // check that the migration restores it.
        let is_high_privilege = |txn: &mut QueryServerWriteTransaction<'_>| {
            txn.internal_search_uuid(UUID_IDM_HIGH_PRIVILEGE)
                .expect("idm_high_privilege missing")
                .attribute_equality(
                    Attribute::Member,
                    &PartialValue::Refer(UUID_IDM_APPROVAL_ADMINS),
                )
        };
        assert!(is_high_privilege(&mut write_txn));
        write_txn
            .internal_modify_uuid(
                UUID_IDM_HIGH_PRIVILEGE,
                &ModifyList::new_remove(
                    Attribute::Member,
                    PartialValue::Refer(UUID_IDM_APPROVAL_ADMINS),
                ),
            )
            .expect("failed to remove high privilege membership");
        assert!(!is_high_privilege(&mut write_txn));

        write_txn
            .internal_apply_domain_migration(DOMAIN_TGT_LEVEL)
            .expect("Unable to set domain level");

        assert!(is_high_privilege(&mut write_txn));

        let fed = write_txn
            .internal_search_uuid(fed_uuid)
            .expect("federation entry lost");
        assert_eq!(
            fed.get_ava_single_url(Attribute::OAuth2Issuer)
                .map(Url::as_str),
            Some("https://idp.example.com/")
        );
        assert_eq!(
            fed.get_ava_single_iutf8(Attribute::OAuth2LinkPolicy),
            Some("manual")
        );
        assert_eq!(
            fed.get_ava_single_iname(Attribute::OAuth2FederationId),
            Some("migrated_fed")
        );

        for uuid in [
            UUID_IDM_APPROVAL_ADMINS,
            UUID_IDM_DELEGATED_HELPDESK,
            UUID_IDM_DELEGATED_USER_ADMIN,
            UUID_IDM_DELEGATED_GROUP_ADMIN,
            UUID_IDM_ACP_OAUTH2_FEDERATION_ADMIN,
            UUID_IDM_ACP_DELEGATED_ROLE_READ,
        ] {
            write_txn
                .internal_search_uuid(uuid)
                .unwrap_or_else(|err| panic!("kubidm builtin entry {uuid} missing: {err:?}"));
        }

        crate::server::access::assert_builtin_acps_all_loaded(&mut write_txn);

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_TGT_LEVEL)]
    async fn test_migrations_prevent_downgrades(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        let mut write_txn = server.write(curtime).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_TGT_LEVEL);

        drop(write_txn);

        // MUST NOT SUCCEED.
        let err = server
            .initialise_helper(curtime, DOMAIN_PREVIOUS_TGT_LEVEL)
            .await
            .expect_err("Domain level was lowered!!!!");

        assert_eq!(err, OperationError::MG0010DowngradeNotAllowed);
    }

    #[qs_test(domain_level=DOMAIN_MIGRATION_FROM_INVALID)]
    async fn test_migrations_prevent_skips(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        let mut write_txn = server.write(curtime).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_MIGRATION_FROM_INVALID);

        drop(write_txn);

        // MUST NOT SUCCEED.
        let err = server
            .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
            .await
            .expect_err("Migration went ahead!!!!");

        assert_eq!(err, OperationError::MG0008SkipUpgradeAttempted);
    }

    #[qs_test(domain_level=DOMAIN_MIGRATION_FROM_MIN)]
    async fn test_migrations_skip_valid(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        // This is a smoke test that X -> Z migrations work for some range. This doesn't
        // absolve us of the need to write more detailed migration tests.
        let mut write_txn = server.write(curtime).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_MIGRATION_FROM_MIN);

        drop(write_txn);

        // MUST SUCCEED.
        server
            .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
            .await
            .expect("Migration failed!!!!");

        // Kubidm: and nothing is skipped, every built-in access control profile is loaded.
        let mut write_txn = server.write(curtime).await.unwrap();
        crate::server::access::assert_builtin_acps_all_loaded(&mut write_txn);
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_11)]
    async fn test_migrations_dl11_dl12(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_11);

        // Make a new person.
        let tuuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        write_txn
            .internal_create(vec![e1])
            .expect("Unable to create user");

        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load user");

        // They still have an id verification key
        assert!(user.get_ava_set(Attribute::IdVerificationEcKey).is_some());

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_12)
            .expect("Unable to set domain level to version 12");

        // post migration verification.
        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load user");

        // The key has been removed.
        assert!(user.get_ava_set(Attribute::IdVerificationEcKey).is_none());

        // New users don't get a key
        let t2uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson2")),
            (Attribute::Uuid, Value::Uuid(t2uuid)),
            (Attribute::Description, Value::new_utf8s("testperson2")),
            (Attribute::DisplayName, Value::new_utf8s("testperson2"))
        );

        write_txn
            .internal_create(vec![e2])
            .expect("Unable to create user");

        let user = write_txn
            .internal_search_uuid(t2uuid)
            .expect("Unable to load user");

        // No key!
        assert!(user.get_ava_set(Attribute::IdVerificationEcKey).is_none());

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_12)]
    async fn test_migrations_dl12_dl13(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_12);

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_13)
            .expect("Unable to set domain level to version 13");

        // post migration verification.

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_13)]
    async fn test_migrations_dl13_dl14(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_13);

        // Create a person without pwd_changed_time
        let tuuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        write_txn
            .internal_create(vec![e1])
            .expect("Unable to create test person");

        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load test person");

        // sanity check
        assert!(user
            .get_ava_single_datetime(Attribute::PasswordChangedTime)
            .is_none());

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_14)
            .expect("Unable to set domain level to version 14");

        // post migration verification.
        // pwd_changed_time should be defaulted to UNIX_EPOCH
        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load test person after migration");

        let pwd_changed = user
            .get_ava_single_datetime(Attribute::PasswordChangedTime)
            .expect("PasswordChangedTime should be set after DL13->DL14 migration");

        assert_eq!(pwd_changed, time::OffsetDateTime::UNIX_EPOCH);

        write_txn.commit().expect("Unable to commit");
    }

    /// Assert whether the database holds `attributetype` and `classtype` entries,
    /// checking each class on its own so that neither can hide behind the other.
    fn assert_db_stored_schema(write_txn: &mut QueryServerWriteTransaction<'_>, present: bool) {
        for class in [EntryClass::AttributeType, EntryClass::ClassType] {
            let filter = filter!(f_eq(Attribute::Class, class.into()));
            let exists = write_txn.internal_exists(&filter).unwrap();
            assert_eq!(exists, present, "db stored {class:?} entries present");
        }
    }

    /// Create a person after a migration, proving the server still accepts writes
    /// and can read them back.
    fn assert_person_create_works(write_txn: &mut QueryServerWriteTransaction<'_>) {
        let tuuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        write_txn
            .internal_create(vec![e1])
            .expect("Unable to create test person");

        write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load test person");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_14)]
    async fn test_migrations_dl14_dl1_11(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_14);

        // Before 1.11 schema is stored in the database. Add custom schema on top of
        // the system schema, as a schema admin could have done.
        let custom_attr_uuid = Uuid::new_v4();
        let custom_attr = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value()),
            (Attribute::Uuid, Value::Uuid(custom_attr_uuid)),
            (
                Attribute::AttributeName,
                Value::new_iutf8(Attribute::TestAttr.as_str())
            ),
            (Attribute::Description, Value::new_utf8s("Test Attribute")),
            (Attribute::MultiValue, Value::new_bool(false)),
            (Attribute::Unique, Value::new_bool(false)),
            (
                Attribute::Syntax,
                Value::new_syntaxs("UTF8STRING").expect("syntax")
            )
        );

        let custom_class_uuid = Uuid::new_v4();
        let custom_class = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClassType.to_value()),
            (Attribute::Uuid, Value::Uuid(custom_class_uuid)),
            (
                Attribute::ClassName,
                Value::new_iutf8(EntryClass::TestClass.as_str())
            ),
            (Attribute::Description, Value::new_utf8s("Test Class")),
            (
                Attribute::May,
                Value::new_iutf8n(Attribute::TestAttr.as_str())
            )
        );

        write_txn
            .internal_create(vec![custom_attr, custom_class])
            .expect("Unable to create custom schema");

        assert_db_stored_schema(&mut write_txn, true);

        write_txn.commit().expect("Unable to commit");

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_1_11)
            .expect("Unable to set domain level to version 1_11");

        // post migration verification.

        // Assert all lingering schema db entries are removed, both system and custom.
        assert_db_stored_schema(&mut write_txn, false);
        assert!(!write_txn.internal_exists_uuid(custom_attr_uuid).unwrap());
        assert!(!write_txn.internal_exists_uuid(custom_class_uuid).unwrap());

        // The in memory schema still serves the server.
        assert_person_create_works(&mut write_txn);

        // Kubidm: no access control profile is skipped.
        assert!(write_txn.get_accesscontrols().get_skipped().is_empty());

        write_txn.commit().expect("Unable to commit");
    }

    /// 1.11.x releases never removed the database stored schema, so a database at
    /// 1.11 can still hold it. The 1.11 -> 1.12 migration must remove it.
    #[qs_test(domain_level=DOMAIN_LEVEL_1_11)]
    async fn test_migrations_dl1_11_to_dl_1_12_removes_db_stored_schema(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_1_11);

        // A database created at 1.11 has no stored schema.
        assert_db_stored_schema(&mut write_txn, false);

        // Store the schema in the database, as an upgrade from 1.10 by a 1.11.x
        // release left it.
        write_txn
            .initialise_schema_core()
            .expect("Unable to store schema in the database");

        assert_db_stored_schema(&mut write_txn, true);

        write_txn.commit().expect("Unable to commit");

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_1_12)
            .expect("Unable to set domain level to version 1_12");

        // post migration verification.
        assert_db_stored_schema(&mut write_txn, false);

        assert_person_create_works(&mut write_txn);

        crate::server::access::assert_builtin_acps_all_loaded(&mut write_txn);

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_1_11)]
    async fn test_migrations_dl1_11_to_dl_1_12(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_1_11);

        // Create an OAuth2 Client

        let oauth2_client_uuid = Uuid::new_v4();
        let oauth2_client_entry = EntryInitNew::from_iter([
            (
                Attribute::Class,
                ValueSetIutf8N::from_iter([
                    EntryClass::Object.into(),
                    EntryClass::Account.into(),
                    EntryClass::OAuth2ResourceServer.into(),
                    EntryClass::OAuth2ResourceServerBasic.into(),
                ])
                .unwrap() as _,
            ),
            (Attribute::Name, ValueSetIname::new("test_oauth2_client")),
            (
                Attribute::DisplayName,
                vs_utf8!("test_oauth2_client".to_string()),
            ),
            (Attribute::Uuid, vs_uuid!(oauth2_client_uuid)),
            (
                Attribute::OAuth2RsOriginLanding,
                ValueSetUrl::new(Url::parse("https://demo.example.com").unwrap()) as ValueSet,
            ),
        ]);

        write_txn
            .internal_create(vec![oauth2_client_entry])
            .expect("Unable to create entries");

        let oauth2_client_entry_pre = write_txn
            .internal_search_uuid(oauth2_client_uuid)
            .expect("Unable to load oauth2 client");

        // sanity check
        assert!(!oauth2_client_entry_pre.has_class(&EntryClass::KeyObjectJweA256GCM));

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_1_12)
            .expect("Unable to set domain level to version 1_12");

        // post migration verification.
        let oauth2_client_entry_pre = write_txn
            .internal_search_uuid(oauth2_client_uuid)
            .expect("Unable to load oauth2 client");

        // Must now have the A256GCM class
        assert!(oauth2_client_entry_pre.has_class(&EntryClass::KeyObjectJweA256GCM));

        // Kubidm: nothing is skipped, every built-in access control profile is loaded.
        crate::server::access::assert_builtin_acps_all_loaded(&mut write_txn);

        write_txn.commit().expect("Unable to commit");
    }
}
