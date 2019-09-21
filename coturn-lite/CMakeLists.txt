cmake_minimum_required(VERSION 3.14)

add_definitions(-DTURN_NO_SQLITE -DTURN_NO_PQ -DTURN_NO_MYSQL  -DTURN_NO_MONGO -DTURN_NO_HIREDIS -DDTLS_SUPPORTED)

set(
        USERDB_MODS
        src/apps/relay/dbdrivers/dbdriver.c
        #src/apps/relay/dbdrivers/dbd_sqlite.c
        #src/apps/relay/dbdrivers/dbd_pgsql.c
        #src/apps/relay/dbdrivers/dbd_mysql.c
        #src/apps/relay/dbdrivers/dbd_mongo.c
        #src/apps/relay/dbdrivers/dbd_redis.c
)

set(
        HIREDIS_MODS
        src/apps/common/hiredis_libevent2.c
)
set(
        SERVERAPP_MODS
        src/apps/relay/mainrelay.c
        src/apps/relay/netengine.c
        #src/apps/relay/libtelnet.c
        src/apps/relay/turn_admin_server.c
        src/apps/relay/userdb.c
        #src/apps/relay/tls_listener.c
        src/apps/relay/dtls_listener.c
        ${HIREDIS_MODS}
        ${USERDB_MODS}
)
set(
        COMMON_MODS
        src/apps/common/apputils.c src/apps/common/ns_turn_utils.c src/apps/common/stun_buffer.c
)

set(
        LIBCLIENTTURN_MODS
        src/client/ns_turn_ioaddr.c src/client/ns_turn_msg_addr.c src/client/ns_turn_msg.c
)

set(
        SERVERTURN_MODS
        ${LIBCLIENTTURN_MODS}
        src/server/ns_turn_allocation.c src/server/ns_turn_maps_rtcp.c src/server/ns_turn_maps.c src/server/ns_turn_server.c
)

set(
        IMPL_MODS
        src/apps/relay/ns_ioalib_engine_impl.c
        src/apps/relay/turn_ports.c
        #src/apps/relay/http_server.c
)


include_directories(
        src/apps/relay/dbdrivers
        src/apps/relay
        src/apps/common
        src/client
        src/server
        src
        src/apps/relay/dbdrivers
)

add_executable(
        coturn
        ${IMPL_MODS}
        ${SERVERAPP_MODS}
        ${COMMON_MODS}
        ${SERVERTURN_MODS}
)

target_link_libraries(
        coturn
        -lrt -lnsl -lresolv -pthread -lcrypto -lssl -levent_core -levent_extra -levent_openssl -levent_pthreads
)