%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2021 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(unit_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).


all() ->
    [
        {group, parallel_tests}
    ].

groups() ->
    [
        {parallel_tests, [parallel], [
            inet_tls_enabled,
            osiris_replication_over_tls_configuration_with_optfile,
            osiris_replication_over_tls_configuration_with_opt
        ]}
    ].

init_per_group(_, Config) -> Config.
end_per_group(_, Config) -> Config.

init_per_testcase(_, Config) -> Config.

end_per_testcase(_, Config) -> Config.

inet_tls_enabled(_) ->
    InitArgs = init:get_arguments(),
    ?assert(rabbit_prelaunch_conf:inet_tls_enabled(InitArgs ++ [{proto_dist,["inet_tls"]}])),
    ?assertNot(rabbit_prelaunch_conf:inet_tls_enabled(InitArgs)),
    ok.

osiris_replication_over_tls_configuration_with_optfile(Config) ->
    FileOk = ?config(data_dir, Config) ++ "inter_node_tls_ok.config",
    InitArgsOk = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_optfile,[FileOk]}
    ],
    ?assertEqual([
        {osiris, [
            {replication_transport,ssl},
            {replication_server_ssl_options, [
                {cacertfile,"/etc/rabbitmq/ca_certificate.pem"},
                {certfile,"/etc/rabbitmq/server_certificate.pem"},
                {keyfile,"/etc/rabbitmq/server_key.pem"},
                {secure_renegotiate,true},
                {verify,verify_peer},
                {fail_if_no_peer_cert,true}
            ]},
            {replication_client_ssl_options, [
                {cacertfile,"/etc/rabbitmq/ca_certificate.pem"},
                {certfile,"/etc/rabbitmq/client_certificate.pem"},
                {keyfile,"/etc/rabbitmq/client_key.pem"},
                {secure_renegotiate,true},
                {verify,verify_peer},
                {fail_if_no_peer_cert,true}
            ]}
        ]}
    ], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgsOk)),

    FileBroken = ?config(data_dir, Config) ++ "inter_node_tls_broken.config",
    InitArgsBroken = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_optfile,[FileBroken]}
    ],
    ?assertEqual([], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgsBroken)),

    FileNotFound = ?config(data_dir, Config) ++ "inter_node_tls_not_found.config",
    InitArgsNotFound = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_optfile,[FileNotFound]}
    ],
    ?assertEqual([], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgsNotFound)),

    ok.

osiris_replication_over_tls_configuration_with_opt(_) ->
    InitArgs = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_opt,["server_cacertfile",
                       "/etc/rabbitmq/ca_certificate.pem"]},
        {ssl_dist_opt,["server_certfile",
                       "/etc/rabbitmq/server_certificate.pem"]},
        {ssl_dist_opt,["server_keyfile",
                       "/etc/rabbitmq/server_key.pem"]},
        {ssl_dist_opt,["server_verify","verify_peer"]},
        {ssl_dist_opt,["server_fail_if_no_peer_cert","true"]},
        {ssl_dist_opt,["client_cacertfile",
                       "/etc/rabbitmq/ca_certificate.pem"]},
        {ssl_dist_opt,["client_certfile",
                       "/etc/rabbitmq/client_certificate.pem"]},
        {ssl_dist_opt,["client_keyfile",
                       "/etc/rabbitmq/client_key.pem"]},
        {ssl_dist_opt,["client_verify","verify_peer"]},
        {ssl_dist_opt,["server_secure_renegotiate","true",
                       "client_secure_renegotiate","true"]}
    ],

    ?assertEqual([
        {osiris, [
            {replication_transport,ssl},
            {replication_server_ssl_options, [
                {cacertfile,"/etc/rabbitmq/ca_certificate.pem"},
                {certfile,"/etc/rabbitmq/server_certificate.pem"},
                {keyfile,"/etc/rabbitmq/server_key.pem"},
                {verify,verify_peer},
                {fail_if_no_peer_cert,true},
                {secure_renegotiate,true}
            ]},
            {replication_client_ssl_options, [
                {cacertfile,"/etc/rabbitmq/ca_certificate.pem"},
                {certfile,"/etc/rabbitmq/client_certificate.pem"},
                {keyfile,"/etc/rabbitmq/client_key.pem"},
                {verify,verify_peer},
                {secure_renegotiate,true}
            ]}
        ]}
    ], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(InitArgs)),

    ExtraInitArgs = [
        {proto_dist,["inet_tls"]},
        {ssl_dist_opt,["server_verify_fun",
                       "{some_module,some_function,some_initial_state}"]},
        {ssl_dist_opt,["server_crl_check",
                       "true"]},
        {ssl_dist_opt,["server_crl_cache",
                       "{ssl_crl_cache, {internal, []}}"]},
        {ssl_dist_opt,["server_reuse_sessions",
                       "save"]},
        {ssl_dist_opt,["server_depth", "1"]},
        {ssl_dist_opt,["server_hibernate_after", "10"]},
        {ssl_dist_opt,["server_ciphers", "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"]},
        {ssl_dist_opt,["server_dhfile", "/some/file"]},
        {ssl_dist_opt,["server_password", "bunnies"]}
    ],

    ?assertEqual([
        {osiris, [
            {replication_transport,ssl},
            {replication_server_ssl_options, [
                {verify_fun,{some_module,some_function,some_initial_state}},
                {crl_check, true},
                {crl_cache, {ssl_crl_cache, {internal, []}}},
                {reuse_sessions, save},
                {depth, 1},
                {hibernate_after, 10},
                {ciphers, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"},
                {dhfile, "/some/file"},
                {password, "bunnies"}
            ]},
            {replication_client_ssl_options, []}
        ]}
    ], rabbit_prelaunch_conf:osiris_replication_over_tls_configuration(ExtraInitArgs)),

    ok.

