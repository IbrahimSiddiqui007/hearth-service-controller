"""Feature-level valid/invalid/edge scenarios with behavioral test traceability.

References reuse integration assertions rather than inflating the test count by
rerunning one test three times. Planned features are never reported as passing.
"""
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]


def node(module, name):
    return 'tests/test_'+module+'.py::test_'+name


FAMILIES={
 'notebook': (
  ('Save current-revision notebook metadata and retain its service identity.',node('completion','identity_host_and_dependency_validation')),
  ('Reject stale revisions, invalid host/identity references or secret-bearing prose without overwriting notes.',node('controller','note_revisions_detect_conflicts_and_preserve_history')),
  ('Keep empty prose and absent optional metadata usable; moving a host clears old runtime access.',node('completion','identity_host_and_dependency_validation'))),
 'discovery': (
  ('Propose observed runtime metadata, review it and preserve owner fields.',node('completion','discovery_diffs_and_missing_require_successful_provider')),
  ('Refuse duplicated/sensitive runtime identities and invalid service definitions.',node('masking','discovery_masks_observations_before_storage_and_refuses_sensitive_handles')),
  ('Incomplete/filtered providers never prove disappearance; an empty review survives restart.',node('completion','discovery_review_survives_restart_and_empty_selection'))),
 'docker': (
  ('Group observed Compose containers and published ports without exporting their environment.',node('agent','compose_discovery_groups_and_does_not_return_environment')),
  ('Refuse controls outside the local runtime/path approval.',node('agent','compose_path_must_match_agent_policy')),
  ('Treat absent/partial runtime observations as unknown, never as verified command success.',node('completion','live_container_state_requires_observation_and_host_operations_serialize'))),
 'systemd': (
  ('Discover loaded and enabled-unloaded approved units.',node('completion','systemd_enabled_unloaded_and_os_unhide')),
  ('Refuse unapproved unit/action vectors.',node('agent','only_allowlisted_argument_vectors_execute')),
  ('Filtering hidden system units never marks them gone.',node('completion','os_filter_cannot_falsely_mark_hidden_unit_missing'))),
 'pm2': (
  ('Inspect and control the exact owned numeric pm2 instance without environment output.',node('extra_runtimes','pm2_agent_scan_control_and_logs_keep_exact_instance')),
  ('Refuse a missing/unowned pm2 daemon before invoking its CLI.',node('extra_runtimes','pm2_refuses_missing_daemon_without_cli_call')),
  ('Omit sensitive instance fields while retaining the verified instance identity.',node('extra_runtimes','pm2_inventory_omits_env_and_actions_use_verified_numeric_instance'))),
 'host': (
  ('Authenticated observations update the registered host and service state.',node('controller','live_agent_flow_and_verified_control')),
  ('Reject wrong physical identity and invalidate old-OS access.',node('windows_inventory','wrong_physical_identity_never_marks_agent_online')),
  ('Missing heartbeats or failed OS-switch scans become stale/unknown.',node('windows_inventory','os_switch_clears_previous_runtime_access_even_when_scan_fails'))),
 'groups': (
  ('Start/stop components in dependency order and preserve all notebooks when splitting.',node('groups','link_split_preserves_notebooks_and_export')),
  ('Reject cycles, nested/multiple/cross-host and double-controlled Compose groups.',node('groups','invalid_groups')),
  ('A failed observation or cancellation halts the group and releases its reservation.',node('groups','group_reservation_and_cancel_release'))),
 'control': (
  ('Allow confirmed fixed runtime actions and audit observed outcomes.',node('controller','demo_controls_are_audited_and_protected')),
  ('Reject unapproved argv and non-allow-listed runtime identities.',node('agent','only_allowlisted_argument_vectors_execute')),
  ('An unobserved command result remains unknown and a busy host cannot be controlled.',node('completion','live_container_state_requires_observation_and_host_operations_serialize'))),
 'dependencies': (
  ('Start verified prerequisites first and show declared reverse relationships.',node('completion','dependency_start_requires_confirmation_and_preflights_all_hosts')),
  ('Reject cycles, unknown references and offline preflight plans before dispatch.',node('completion','identity_host_and_dependency_validation')),
  ('Handle diamonds and deep graphs without duplicate starts or recursion failure.',node('completion','dependency_diamonds_and_deep_graphs'))),
 'health': (
  ('Record successful checks, latency and matching outage/recovery incidents.',node('controller','health_configuration_results_and_demo_network_isolation')),
  ('Reject unsafe/malformed health targets and out-of-range check settings.',node('controller','invalid_health_settings_rejected')),
  ('Timeouts, old in-flight results and empty histories preserve unknown coverage.',node('completion','incident_lifecycle_and_old_inflight_checks'))),
 'uptime': (
  ('Weight observed healthy/unhealthy intervals rather than counting samples.',node('completion','weighted_uptime_gaps_and_unequal_intervals')),
  ('Do not carry results across a changed target signature.',node('controller','changed_health_destination_starts_a_new_series')),
  ('Empty histories return unknown percentages and bounded observation gaps.',node('completion','weighted_uptime_gaps_and_unequal_intervals'))),
 'resources': (
  ('Collect scoped process/container/cgroup memory and counter observations.',node('observability','docker_resources_locations_policy_and_group_aggregation')),
  ('Permission denial or malformed/reset counters never produce invented zero rates.',node('observability','process_memory_start_and_permissions')),
  ('Warmup, PID reuse, reboot and missing samples keep rates unknown.',node('observability','rates_reset_gaps_and_interfaces_are_unknown'))),
 'alerts': (
  ('Queue one health failure/recovery notification for each incident.',node('alerts','health_failure_and_recovery_enqueue_once_per_incident')),
  ('Reject unsafe destinations, literal tokens and invalid notification preferences.',node('alerts','notification_profile_rejects_unsafe_destinations_and_literal_tokens')),
  ('Retries are bounded; concurrent flushes deliver a row once and demo never sends.',node('alerts','concurrent_flush_does_not_deliver_same_row_twice'))),
 'ping': (
  ('Use fixed platform ICMP arguments for approved targets.',node('completion','icmp_uses_fixed_arguments_and_records_outcome')),
  ('Reject injected hostnames/flags before creating a ping process.',node('completion','icmp_uses_fixed_arguments_and_records_outcome')),
  ('Timeouts and unavailable probes return failure without target credential disclosure.',node('health','health_timeout_does_not_echo_target_secrets'))),
 'wake': (
  ('Build/send a magic packet only to the configured destination through a mocked socket.',node('wake','magic_packet_uses_only_configured_destination_with_mock_socket')),
  ('Reject unapproved MAC/IP/port profiles and unconfirmed requests.',node('wake','wake_profiles_reject_unapproved_destinations')),
  ('Cooldown and socket failure never infer the host became online.',node('wake','live_wake_socket_failure_audits_unknown_and_releases_operation'))),
 'power': (
  ('Confirmed, fresh identity-bound plans use fixed ordinary-account actions and durable intent.',node('power','controller_plan_reservations_unknown_outcome_ack_and_no_auto_writes')),
  ('Reject unapproved/stale/wrong-identity profiles, null GUI domains and elevated agents.',node('power','power_plan_requires_local_approval_identity_freshness_and_no_busy_operations')),
  ('Lost results remain held; acknowledgement tombstones delayed requests without replay.',node('power','acknowledging_unreceived_intent_tombstones_delayed_dispatch'))),
 'schedules': (
  ('Dispatch an approved grouped window once, in dependency order, in its configured timezone.',node('schedules','group_schedule_valid_preflight_order_and_component_rejection')),
  ('Reject invalid/null timezone, cron, child enrollment or absent component consent.',node('schedules','timezone_valid_invalid_null_and_dst_edges')),
  ('Skip nonexistent/repeated DST minutes, offline windows, clock rollback and interrupted results.',node('schedules','restart_clock_rollback_conflicting_rules_and_crash_never_retry'))),
 'idle': (
  ('Verified uninterrupted activity profiles stop the whole application and permit normal manual wake.',node('group_idle','continuous_all_component_activity_stops_in_order_and_manual_wake')),
  ('Active/unknown component signals, permissions or external dependents inhibit every stop.',node('group_idle','missing_component_permission_and_external_dependents_prevent_all_probes')),
  ('A changed component/profile or observation gap resets the idle window.',node('group_idle','changed_component_resets_continuous_activity_window'))),
 'documentation': (
  ('Save installation/recovery prose, previous versions and portable notebook exports.',node('service_documentation','setup_recovery_notes_history_export_and_secret_exclusion')),
  ('Reject secret-bearing prose, marker injection and stale revisions.',node('controller','secret_and_marker_notes_rejected')),
  ('Empty owner sections stay editable and do not imply a verified backup.',node('feature_api_cases','public_notebook_contract[null-edge-Living service card]'))),
 'locations': (
  ('Retain typed working/config/data/log locations and rooted document previews.',node('observability','runtime_documents_keep_approved_roots_and_masking')),
  ('Refuse traversal and previews outside approved service roots.',node('agent','readonly_file_scope_and_secret_exclusion')),
  ('Unavailable/binary/large text sources remain explicit bounded/read-only views.',node('completion','large_text_binary_download_and_blocked_secrets'))),
 'history': (
  ('Expose scoped semantic controls, notes, config versions and incident history.',node('configuration','git_versions_diff_restore_scope_and_whitespace')),
  ('Reject unverified/scoped-out versions and prospective Git preparation failures.',node('config_operations','git_preparation_failure_never_calls_remote_write')),
  ('Restart/interruption keeps prepared versions unknown and checkpoints intact.',node('config_operations','restart_marks_prepared_versions_unknown_and_retains_checkpoints'))),
 'manifest': (
  ('Preview/apply valid JSON/YAML definitions and preserve repeat-import revisions.',node('controller','manifest_preview_apply_idempotent')),
  ('Reject malformed/secret/injected/cyclic/unknown references without writes.',node('controller','invalid_manifests_do_not_change_registry')),
  ('Refuse stale previews and duplicate IDs rather than overwriting notebooks.',node('controller','manifest_stale_preview_rejected'))),
 'export': (
  ('Export linked portable Markdown with documented access and vault references.',node('controller','export_is_portable_and_has_backlinks')),
  ('Reject filename case collisions and embedded sync-marker injection.',node('controller','vault_filename_case_collisions_and_embedded_markers_rejected')),
  ('Preserve unrelated vault files and report broken-marker conflicts.',node('controller','obsidian_preserves_unknown_files_and_broken_markers'))),
 'recording': (
  ('Explicit opt-in sessions persist bounded masked recordings and scoped casts.',node('terminal','optin_recording_masked_and_ticket_single_use')),
  ('Reject wrong/expired/reused attach tickets and absent recording permission.',node('terminal','terminal_confirmation_wrong_ticket_origin_and_host_reservation')),
  ('No recording selection means metadata only; split secrets and entry limits are bounded.',node('terminal','demo_terminal_audits_metadata_only_without_recording_and_never_executes'))),
 'snapshot': (
  ('Capture approved before/after metadata and selected watch-file hashes, not contents.',node('installation','snapshot_capture_demo_no_agent_and_review_pruning')),
  ('Reject injected content, duplicates and secret-bearing snapshot metadata.',node('installation','untrusted_snapshot_rejects_content_duplicates_and_secrets')),
  ('Incomplete/different scopes and budget overflow never prove removal.',node('installation','partial_or_different_scope_never_infers_removed_files'))),
 'review': (
  ('Save ordered reviewed exclusions/instructions and scoped exports.',node('installation','history_import_review_conflicts_export_and_service_scope')),
  ('Refuse stale review revisions, foreign service sessions and fictitious history casts.',node('installation','history_import_review_conflicts_export_and_service_scope')),
  ('Keep original masked evidence and mark every reconstructed instruction unverified.',node('installation','snapshot_capture_demo_no_agent_and_review_pruning'))),
 'shellhistory': (
  ('Parse explicit Bash/Zsh/Fish excerpts and keep relevant service commands in order.',node('installation','history_formats')),
  ('Omit unrelated and secret-bearing commands without storing the pasted raw history.',node('installation','history_filters_service_tokens_ports_and_secrets')),
  ('Empty/unmatched imports never imply installation success or a real terminal cast.',node('installation','history_import_review_conflicts_export_and_service_scope'))),
 'files': (
  ('Preview approved UTF-8 files and download bounded permitted data.',node('completion','large_text_binary_download_and_blocked_secrets')),
  ('Refuse path traversal, symlink escape and secret filename access.',node('agent','readonly_file_scope_and_secret_exclusion')),
  ('Large/binary files remain bounded/read-only and missing roots are refused.',node('completion','demo_file_download_is_attachment'))),
 'edit': (
  ('Edit approved owned UTF-8 files with etags, syntax checks and prospective versions.',node('configuration','atomic_edit_permissions_etag_validation_and_line_endings')),
  ('Secret/malformed content, stale etags and changing permissions never replace the original.',node('configuration','secrets_and_invalid_config_never_enter_git')),
  ('Native replacement uncertainty retains recovery evidence rather than blind retry.',node('file_metadata','partial_native_replacement_retains_candidate_and_reports_uncertain'))),
 'capture': (
  ('Opt-in capture records a changed verified file as a scoped Git version.',node('capture','demo_capture_opt_in_baseline_change_and_service_scope')),
  ('Reject malformed/secret sources, concurrent capture and host moves.',node('capture','capture_concurrent_requests_and_host_moves_are_refused')),
  ('Scheduled capture honors intervals and its per-pass budget without changing notes.',node('capture','scheduled_capture_caps_three_and_honors_intervals_without_changing_notes'))),
 'logs': (
  ('Read/follow permitted bounded masked output and close owned follower processes.',node('log_stream','follower_child_cleanup_masking_and_fixed_args')),
  ('Refuse unauthorized sources and unsafe file-log paths.',node('extra_runtimes','file_logs_are_rooted_bounded_and_masked')),
  ('Split secrets, rotation, disconnect and follower budgets terminate safely.',node('log_stream','file_stream_holds_split_secret_and_stops_rotation'))),
 'terminal': (
  ('Signed owner-bound tickets open approved mocked PTYs and bounded resize/input.',node('terminal','live_gateway_signs_every_agent_request_and_cleans_up')),
  ('Refuse invalid profile/hash, wrong origin/ticket and recent-owner-auth failures.',node('terminal','terminal_confirmation_profile_hash_and_limits')),
  ('Idle/absolute/polling limits and profile changes close sessions without inheriting tokens.',node('terminal','lost_controller_polling_and_changed_profile_revoke_session'))),
 'ai': (
  ('Explicit model requests use bounded masked context and retain advice-only labels.',node('ai','ai_masks_known_secret_patterns_and_never_executes')),
  ('Reject unsafe origins, missing models, malformed responses and secret-bearing drafts.',node('ai','draft_rejects_bad_model_responses')),
  ('Disabled/unreachable AI does not call a model, execute commands or save prose automatically.',node('installation','demo_ai_drafts_are_explicit_and_do_not_save_or_contact_models'))),
 'credentials': (
  ('Store and export vault pointers/usernames without password fields.',node('controller','credential_pointers_export_and_reject_secret_fields')),
  ('Reject literal secret fields and unsafe vault reference URLs.',node('feature_api_cases','public_notebook_contract[invalid-Credential shortcuts]')),
  ('Empty pointer lists and absent usernames remain valid and reveal no vault contents.',node('feature_api_cases','public_notebook_contract[null-edge-Credential shortcuts]'))),
 'secrets': (
  ('Persist category-only findings and revision-checked owner links.',node('secret_findings','rejected_draft_review_is_scoped_revision_checked_and_value_free')),
  ('Reject unsafe/stale/cross-service links; secret filenames never expose source content.',node('secret_findings','native_exact_file_scanning_preserves_exclusions_and_scope')),
  ('Deduplicate bounded findings; environment references do not produce false findings.',node('secret_findings','safe_environment_reference_does_not_create_finding'))),
 'masking': (
  ('Mask assignments, recognized tokens and private keys before display/audit storage.',node('masking','multiline_keys_recognized_tokens_entropy_and_audit_storage')),
  ('Sensitive runtime handles never enter a controllable discovery definition.',node('masking','discovery_masks_observations_before_storage_and_refuses_sensitive_handles')),
  ('Hold split-output secrets/private-key prompts until safe bounded redaction.',node('terminal','recording_buffers_split_secrets_private_keys_and_sensitive_prompts'))),
 'persistence': (
  ('Compare scoped startup/cron/listener metadata without executing persisted commands.',node('persistence','demo_review_stale_checks_and_no_runtime_permission_changes')),
  ('Reject malformed/extra provider actions and secret metadata.',node('persistence','invalid_inventory_and_arbitrary_remote_fields')),
  ('Incomplete providers retain prior entries without false removal.',node('persistence','partial_provider_does_not_report_removal'))),
 'ingress': (
  ('Accept loopback or the verified local Tailscale identity with owner auth.',node('binding','private_listener')),
  ('Reject broad/unresolved listeners, bad origins and DNS rebinding.',node('controller','auth_origin_and_dns_rebinding_protection')),
  ('A stale/mismatched Tailscale address cannot become a remote bind.',node('binding','tailnet_listener_must_match_running_local_tailscale_identity'))),
 'login': (
  ('Correct password/TOTP creates a revocable owner session.',node('login','login_session_logout_and_totp_replay')),
  ('Bad/null credentials and forbidden origin are refused with bounded rate limits.',node('login','invalid_credentials_rate_limit_and_origin')),
  ('Session expiry, changed configuration and remote HTTP fail closed.',node('login','secure_cookie_expiry_remote_http_and_configuration_change'))),
 'auth': (
  ('Accept exact independent signed body/path/query requests with a private replay store.',node('signatures','signed_read_body_query_and_durable_replay')),
  ('Refuse missing/wrong bearer, bad/short keys and invalid nonces.',node('agent','agent_refuses_missing_or_wrong_token')),
  ('Duplicate or restarted replay state cannot execute a signed mutation twice.',node('signatures','signed_read_body_query_and_durable_replay'))),
 'audit': (
  ('Persist authenticated action/write intent and fixed-template HTTP metadata.',node('audit_journal','write_audit_valid_invalid_null_preserves_values_outside_storage[valid]')),
  ('Record refused invalid/null writes without their credential/body values.',node('audit_journal','write_audit_valid_invalid_null_preserves_values_outside_storage[invalid]')),
  ('Interrupted/restarted requests remain unknown and never replay; future restore routes inherit the hook.',node('audit_journal','interruption_and_restart_stay_unknown_and_never_replay'))),
 'windows': (
  ('Observe scoped software/process/socket metadata and curated product documentation.',node('windows_inventory','registry_metadata_never_reads_uninstall_commands_and_deduplicates_views')),
  ('Wrong physical identity and arbitrary remote links/actions cannot replace approved inventory.',node('windows_inventory','wrong_physical_identity_does_not_replace_cached_inventory')),
  ('Unavailable providers and OS changes preserve explicit stale/unknown evidence.',node('windows_inventory','snapshot_reports_permission_gaps_without_claiming_empty_complete_scopes'))),
 'software': (
  ('Query local Linux package metadata/macOS bundles without launching applications.',node('software_platforms','linux_package_providers_only_query_local_database')),
  ('Reject wrong identities/unsafe guides and omit execution arguments.',node('software_platforms','software_identity_rejection_and_demo_no_contact')),
  ('Permission/provider gaps remain incomplete; OS switches keep prior observations stale.',node('software_platforms','snapshot_scopes_physical_identity_and_permission_gaps'))),
 'obsidian': (
  ('Sync owner-note markers and export linked portable notebooks.',node('controller','obsidian_roundtrip_and_conflict_preservation')),
  ('Conflicting edits or missing markers never overwrite either owner version.',node('controller','obsidian_preserves_unknown_files_and_broken_markers')),
  ('Unrelated files and vault settings survive repeated sync.',node('controller','obsidian_preserves_unknown_files_and_broken_markers'))),
 'deployment': (
  ('Private startup/config contracts are portable and leave native permissions opt-in.',node('binding','private_listener')),
  ('Agent CLI refuses root before reading/installing configuration.',node('agent','agent_cli_refuses_root_before_reading_configuration')),
  ('An empty live installation starts without demo data or unsolicited telemetry.',node('observability','live_start_does_not_append_demo_telemetry'))),
 'api': (
  ('Authenticated REST/state/event/log transports expose permitted data only.',node('read_sockets','read_websockets_require_auth_and_origin_and_close_cleanly')),
  ('Refuse missing authentication, bad origins and unsafe request settings.',node('controller','auth_origin_and_dns_rebinding_protection')),
  ('Disconnected/cancelled sessions close followers and leave uncertain outcomes explicit.',node('terminal','live_gateway_signs_every_agent_request_and_cleans_up'))),
}

# IDs preserve the complete supplied ledger order, including the three additions.
ASSIGNMENTS={
 'notebook':[4,39,40,41,45,138], 'discovery':[13,17,18,46,47], 'docker':[8,9,131], 'systemd':[10,14], 'pm2':[11],
 'host':[5,6,7,23], 'groups':[15,16], 'control':[19,21,38], 'dependencies':[22,44,127], 'health':[24,26], 'uptime':[25],
 'resources':[27,130], 'alerts':[28,29], 'ping':[32], 'wake':[33], 'power':[34], 'schedules':[35], 'idle':[36,37],
 'documentation':[39,45], 'locations':[42,43], 'history':[48,65,67,68], 'manifest':[51,132], 'export':[50],
 'recording':[52,53,76], 'snapshot':[54,55], 'review':[56,57,60], 'shellhistory':[58,59], 'files':[61,64,70,119],
 'edit':[62,69], 'capture':[66], 'logs':[71,72,73], 'terminal':[74,75,77], 'ai':[78,79,80,81,82,83,84,85],
 'credentials':[86,87], 'secrets':[88,89], 'masking':[90], 'persistence':[106], 'ingress':[115], 'login':[116],
 'auth':[117,118], 'audit':[120], 'windows':[136,141], 'software':[142], 'obsidian':[137], 'deployment':[121,122,123], 'api':[124]
}

PUBLIC_SCENARIOS={
 'Central dashboard': ('Return demo workspace status and all eight registered services.', 'Return 404 for an unknown service without synthesizing a card.', 'An absent host filter returns an empty service list.'),
 'Service grid and filters': ('Port query 25565 selects Minecraft.', 'A query with no matching registry record returns no cards.', 'An empty query returns every registered service.'),
 'Search': ('Find Minecraft by its recorded port 25565.', 'An unmatched search returns an empty list.', 'Clearing the search returns all eight demo services.'),
 'Access information': ('Accept a reviewed manifest with an HTTP URL and TCP port.', 'Reject a javascript URL during manifest validation.', 'Accept an empty optional URL and port list.'),
 'Credential shortcuts': ('Save a current-revision username and HTTPS vault reference.', 'Reject a javascript vault reference without changing credentials.', 'Accept an empty credential list without inventing a secret.'),
 'Notebook header/top banner': ('Retain the service name, host name and Compose runtime for the cover.', 'Unknown notebook identity returns 404.', 'Empty notes and description retain the Minecraft service identity.'),
 'Living service card': ('Expose the registered service identity, host and runtime.', 'Unknown service identity returns 404.', 'Empty optional prose leaves the service identity intact.'),
}

# Each F10 row has its own expected behavior; shared integration assertions are
# referenced explicitly rather than counted again as separate pytest functions.
BACKUP_SCENARIOS={
 92: [('Back up approved service paths with notebook data in one snapshot.','backup_scope_password_source_and_documentation[valid]'),('Missing storage refuses dispatch without local fallback.','backup_scope_password_source_and_documentation[invalid]'),('Absent repository password refuses tool execution.','backup_scope_password_source_and_documentation[null-edge]')],
 93: [('Use the approved mounted repository for a completed backup.','backup_scope_password_source_and_documentation[valid]'),('An unmounted share executes no backup command.','backup_scope_password_source_and_documentation[invalid]'),('Missing password keeps the storage workflow unavailable.','backup_scope_password_source_and_documentation[null-edge]')],
 94: [('A current daily window dispatches once without blocking polling.','backup_schedule_skips_restart_gaps_and_does_not_block_polling'),('A stale reviewed fingerprint refuses manual dispatch.','backup_api_plan_revision_guards_null_and_durable_audit[invalid]'),('Restart gaps and repeated windows never replay.','backup_schedule_skips_restart_gaps_and_does_not_block_polling')],
 95: [('Delete only reviewed immutable data snapshot IDs, preserving new arrivals.','retention_deletes_only_reviewed_ids_even_if_repository_changes'),('A stale retention fingerprint refuses deletion.','retention_is_scoped_reviewed_and_never_prunes_safety_snapshots[invalid]'),('Absent local retention approval refuses deletion; no prune runs.','retention_is_scoped_reviewed_and_never_prunes_safety_snapshots[edge]')],
 96: [('Observe stop, copy, restart and post-restore health in the demo workflow.','consistent_backup_stops_copies_restarts_and_restore_requires_health'),('A locally unapproved restore never copies files.','restore_has_preview_safety_snapshot_and_preserves_extra_files[invalid]'),('Unknown runtime state refuses copying and preserves current data.','restore_has_preview_safety_snapshot_and_preserves_extra_files[edge]')],
 97: [('Delegate approved paths to restic with a private password environment, never password argv.','backup_scope_password_source_and_documentation[valid]'),('Missing storage cannot start the encrypted repository operation.','backup_scope_password_source_and_documentation[invalid]'),('No password means no restic invocation; no unencrypted fallback.','backup_scope_password_source_and_documentation[null-edge]')],
 98: [('Use the approved environment reference without returning the password.','backup_scope_password_source_and_documentation[valid]'),('Unavailable storage refuses use of the credential.','backup_scope_password_source_and_documentation[invalid]'),('Missing environment value refuses dispatch without attempting vault login.','backup_scope_password_source_and_documentation[null-edge]')],
 99: [('Include service Markdown and approved config paths in the same backup command.','backup_scope_password_source_and_documentation[valid]'),('Refuse a stale reviewed backup before accepting a new snapshot.','backup_api_plan_revision_guards_null_and_durable_audit[invalid]'),('Returned notebook prose is masked and unknown response fields are discarded.','agent_result_is_whitelisted_before_any_storage')],
 100: [('Record a simulated successful backup and selected snapshot in durable history.','backup_api_plan_revision_guards_null_and_durable_audit[valid]'),('A refused stale backup is audited without inventing a successful run.','backup_api_plan_revision_guards_null_and_durable_audit[invalid]'),('Interrupted runs remain unknown and held across restart.','backup_failure_alert_and_cross_action_hold_survive_restart')],
 101: [('Preview regular files in a scoped immutable snapshot.','restore_preview_rejects_unsafe_archive_metadata_before_writes[valid]'),('Traversal metadata refuses preview before writes.','restore_preview_rejects_unsafe_archive_metadata_before_writes[invalid]'),('A symlink archive remains unrestorable.','restore_preview_rejects_unsafe_archive_metadata_before_writes[edge]')],
 102: [('Stop, restore, restart and run the configured health check.','consistent_backup_stops_copies_restarts_and_restore_requires_health'),('Local restore permission is required before copying.','restore_has_preview_safety_snapshot_and_preserves_extra_files[invalid]'),('Unknown runtime state leaves current data untouched.','restore_has_preview_safety_snapshot_and_preserves_extra_files[edge]')],
 103: [('Complete the safety snapshot before restore and preserve extra current files.','restore_has_preview_safety_snapshot_and_preserves_extra_files[valid]'),('Unapproved restore creates no safety snapshot or target writes.','restore_has_preview_safety_snapshot_and_preserves_extra_files[invalid]'),('Unknown runtime refuses safety/copy and keeps original files.','restore_has_preview_safety_snapshot_and_preserves_extra_files[edge]')],
 104: [('An interrupted backup enqueues one failure alert and retains an inspection hold.','backup_failure_alert_and_cross_action_hold_survive_restart'),('A stale manual request is refused and durably audited.','backup_api_plan_revision_guards_null_and_durable_audit[invalid]'),('Restart preserves uncertain history and blocks conflicting controls.','backup_failure_alert_and_cross_action_hold_survive_restart')],
}

def cases():
    ledger=json.loads((ROOT/'docs/feature-status.json').read_text(encoding='utf-8'))
    rows=[row for section in ledger['sections'] for row in section['rows']]
    groups={identifier:name for name,ids in ASSIGNMENTS.items() for identifier in ids}
    result=[]
    for index,row in enumerate(rows,1):
        if index in (1,3,39,41,49,87,138):
            triplet=[(scenario,node('feature_api_cases','public_notebook_contract['+case+'-'+row[0]+']')) for scenario,case in zip(PUBLIC_SCENARIOS[row[0]],('valid','invalid','null-edge'))]
        elif index==21:
            triplet=[(scenario,node('feature_api_cases','bulk_action_scope['+case+']')) for scenario,case in zip(('Selected Minecraft and Ollama controls both succeed and change only their states.', 'An unknown selected service returns 404 and leaves other states unchanged.', 'An empty selection makes no control requests and leaves both services running.'),('valid','invalid','null-edge'))]
        elif index in (139,140):
            triplet=[(scenario, 'node:'+row[0]+' / '+case) for scenario,case in zip(('Apply and persist supported '+row[0]+' preferences.', 'Unsupported '+row[0]+' values fall back to validated defaults.', 'Null/corrupt storage and system-theme changes keep '+row[0]+' usable.'),('valid','invalid','null-edge'))]
        elif index==2:
            triplet=[('390px layout and interactive tabs fit without horizontal document overflow.','browser:mobile.valid'),('Offline-host controls are disabled on a narrow viewport.','browser:mobile.invalid'),('320px viewport and large text remain navigable without document overflow.','browser:mobile.edge')]
        elif index==143:
            triplet=[('Approved current-user LaunchAgent controls use exact fixed domain/path/hash.',node('launchd_control','launchagent_actions_are_exact_current_user_domain')),('Wrong domain, Apple jobs, changed hash or root accounts cannot mutate native services.',node('launchd_control','wrong_domain_changed_hash_or_apple_job_never_mutates')),('Unloaded approved jobs remain observable; missing native permissions remain explicit.',node('launchd_control','inventory_keeps_unloaded_approved_jobs_and_never_exports_argv'))]
        elif index in BACKUP_SCENARIOS:
            triplet=[(scenario,node('backups',test)) for scenario,test in BACKUP_SCENARIOS[index]]
        elif row[4]=='Not started':
            triplet=[('Planned valid scenario: '+row[1],None),('Planned invalid scenario: refuse unapproved targets, references or actions for '+row[0]+' without mutations.',None),('Planned null/edge scenario: absent provider/input stays unavailable; '+row[0]+' must not invent success or silently queue actions.',None)]
        elif index in groups:
            triplet=FAMILIES[groups[index]]
        else:
            raise ValueError('Missing explicit feature cases: '+row[0])
        for kind,(scenario,reference) in zip(('valid','invalid','edge'),triplet):
            result.append({'id':f'F{index:03d}-{kind}','feature_id':f'F{index:03d}','feature':row[0],'description':row[1],
                           'implementation':row[4],'kind':kind,'scenario':scenario,'test':reference,
                           'target_verification':'deferred by owner' if index in (62,118,121,122,130,143) else 'mocked/source evidence; not deployed'})
    return result
