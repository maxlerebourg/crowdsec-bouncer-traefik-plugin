package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

// pluginVersion is what the plugin reports to the Crowdsec LAPI.
//
// Do not edit by hand: the "Release (1/2) Prepare" workflow bumps it in the
// commit that gets tagged, so the released source always matches its tag.
// Renovate must not touch it either — it can only see a tag once it exists,
// which is what made releases report the previous version (#322, #363).
var pluginVersion = "v1.7.0" //nolint:gochecknoglobals
