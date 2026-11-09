//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

// Peer-to-peer unicast tests (no router) with one listening node (H) and two connecting nodes (A and B).
// Entity ids are only unique per node, so A and B declare their entities with the same ids: H must keep them apart.

#undef NDEBUG
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zenoh-pico.h"
#include "zenoh-pico/session/liveliness.h"
#include "zenoh-pico/session/utils.h"

#if Z_FEATURE_MULTI_THREAD == 1 && Z_FEATURE_UNICAST_PEER == 1 && Z_FEATURE_LINK_TCP == 1 &&                          \
    Z_FEATURE_LIVELINESS == 1 && Z_FEATURE_SUBSCRIPTION == 1 && Z_FEATURE_PUBLICATION == 1 && Z_FEATURE_QUERY == 1 && \
    Z_FEATURE_QUERYABLE == 1 && Z_FEATURE_INTEREST == 1 && Z_FEATURE_MATCHING == 1 &&                                 \
    Z_FEATURE_LOCAL_SUBSCRIBER == 0 && Z_FEATURE_LOCAL_QUERYABLE == 0

#define WAIT_TIMEOUT_MS 5000
#define LIVELINESS_GET_MAX_MS 1000

#define assert_ok(x)                            \
    {                                           \
        int ret = (int)x;                       \
        if (ret != Z_OK) {                      \
            printf("%s failed: %d\n", #x, ret); \
            assert(false);                      \
        }                                       \
    }

static const char *TOKEN_A = "test/peerdecl/token/a";
static const char *TOKEN_B = "test/peerdecl/token/b";
static const char *TOKEN_ALL = "test/peerdecl/token/**";
static const char *QBL_A = "test/peerdecl/qbl/a";
static const char *QBL_B = "test/peerdecl/qbl/b";
static const char *DATA_KE = "test/peerdecl/data";

static uint16_t g_base_port = 0;

static bool keyexpr_is(const z_loaned_keyexpr_t *ke, const char *expected) {
    z_view_string_t ks;
    z_keyexpr_as_view_string(ke, &ks);
    size_t len = z_string_len(z_loan(ks));
    return len == strlen(expected) && strncmp(z_string_data(z_loan(ks)), expected, len) == 0;
}

typedef bool (*cond_fn_t)(void *arg);

static bool wait_until(cond_fn_t cond, void *arg, unsigned long timeout_ms) {
    z_clock_t start = z_clock_now();
    while (!cond(arg)) {
        if (z_clock_elapsed_ms(&start) > timeout_ms) {
            return false;
        }
        z_sleep_ms(10);
    }
    return true;
}

/*------------------ Sessions ------------------*/

static void make_locator(char *buf, size_t len, uint16_t port) {
    snprintf(buf, len, "tcp/127.0.0.1:%u", (unsigned)port);
}

static void open_listener(z_owned_session_t *s, uint16_t port) {
    char locator[64];
    make_locator(locator, sizeof(locator), port);
    z_owned_config_t c;
    z_config_default(&c);
    zp_config_insert(z_loan_mut(c), Z_CONFIG_MODE_KEY, "peer");
    zp_config_insert(z_loan_mut(c), Z_CONFIG_LISTEN_KEY, locator);
    assert_ok(z_open(s, z_move(c), NULL));
}

static void open_connector(z_owned_session_t *s, uint16_t port) {
    char locator[64];
    make_locator(locator, sizeof(locator), port);
    z_owned_config_t c;
    z_config_default(&c);
    zp_config_insert(z_loan_mut(c), Z_CONFIG_MODE_KEY, "peer");
    zp_config_insert(z_loan_mut(c), Z_CONFIG_CONNECT_KEY, locator);
    assert_ok(z_open(s, z_move(c), NULL));
}

static void count_zid(const z_id_t *id, void *arg) {
    _ZP_UNUSED(id);
    (*(size_t *)arg)++;
}

static size_t peers_count(const z_loaned_session_t *s) {
    size_t count = 0;
    z_owned_closure_zid_t cb;
    z_closure(&cb, count_zid, NULL, &count);
    assert_ok(z_info_peers_zid(s, z_move(cb)));
    return count;
}

typedef struct {
    const z_loaned_session_t *s;
    size_t expected;
} peers_cond_t;

static bool has_peers(void *arg) {
    peers_cond_t *c = (peers_cond_t *)arg;
    return peers_count(c->s) == c->expected;
}

static void wait_peers(const z_loaned_session_t *s, size_t expected) {
    peers_cond_t c = {.s = s, .expected = expected};
    assert(wait_until(has_peers, &c, WAIT_TIMEOUT_MS));
}

/*------------------ Liveliness get ------------------*/

typedef struct {
    atomic_uint total;
    atomic_uint a;
    atomic_uint b;
    atomic_bool done;
} get_ctx_t;

static void get_ctx_init(get_ctx_t *ctx) {
    atomic_store(&ctx->total, 0);
    atomic_store(&ctx->a, 0);
    atomic_store(&ctx->b, 0);
    atomic_store(&ctx->done, false);
}

static void get_reply_handler(z_loaned_reply_t *reply, void *arg) {
    get_ctx_t *ctx = (get_ctx_t *)arg;
    assert(z_reply_is_ok(reply));
    const z_loaned_keyexpr_t *ke = z_sample_keyexpr(z_reply_ok(reply));
    atomic_fetch_add(&ctx->total, 1);
    if (keyexpr_is(ke, TOKEN_A)) {
        atomic_fetch_add(&ctx->a, 1);
    } else if (keyexpr_is(ke, TOKEN_B)) {
        atomic_fetch_add(&ctx->b, 1);
    }
}

static void get_drop_handler(void *arg) {
    get_ctx_t *ctx = (get_ctx_t *)arg;
    atomic_store(&ctx->done, true);
}

static bool get_is_done(void *arg) { return atomic_load(&((get_ctx_t *)arg)->done); }

// Run a liveliness get and check that it completes in bounded time
static void liveliness_get(const z_loaned_session_t *s, const char *keyexpr, get_ctx_t *ctx) {
    get_ctx_init(ctx);
    z_view_keyexpr_t ke;
    assert_ok(z_view_keyexpr_from_str(&ke, keyexpr));
    z_owned_closure_reply_t cb;
    z_closure(&cb, get_reply_handler, get_drop_handler, ctx);
    z_clock_t start = z_clock_now();
    assert_ok(z_liveliness_get(s, z_loan(ke), z_move(cb), NULL));
    assert(wait_until(get_is_done, ctx, LIVELINESS_GET_MAX_MS));
    printf("  liveliness get on '%s': %u replies in %lums\n", keyexpr, atomic_load(&ctx->total),
           z_clock_elapsed_ms(&start));
}

typedef struct {
    const z_loaned_session_t *s;
    unsigned expected;
} get_cond_t;

static bool get_returns(void *arg) {
    get_cond_t *c = (get_cond_t *)arg;
    get_ctx_t ctx;
    liveliness_get(c->s, TOKEN_ALL, &ctx);
    return atomic_load(&ctx.total) == c->expected;
}

/*------------------ Liveliness subscriber ------------------*/

typedef struct {
    atomic_uint put_a;
    atomic_uint put_b;
    atomic_uint del_a;
    atomic_uint del_b;
} token_events_t;

static void token_events_handler(z_loaned_sample_t *sample, void *arg) {
    token_events_t *ev = (token_events_t *)arg;
    const z_loaned_keyexpr_t *ke = z_sample_keyexpr(sample);
    bool is_put = z_sample_kind(sample) == Z_SAMPLE_KIND_PUT;
    if (keyexpr_is(ke, TOKEN_A)) {
        atomic_fetch_add(is_put ? &ev->put_a : &ev->del_a, 1);
    } else if (keyexpr_is(ke, TOKEN_B)) {
        atomic_fetch_add(is_put ? &ev->put_b : &ev->del_b, 1);
    }
}

static bool atomic_is_one(void *arg) { return atomic_load((atomic_uint *)arg) == 1; }

/*------------------ Data / queries ------------------*/

static void count_sample(z_loaned_sample_t *sample, void *arg) {
    _ZP_UNUSED(sample);
    atomic_fetch_add((atomic_uint *)arg, 1);
}

static void reply_with_node_name(z_loaned_query_t *query, void *arg) {
    const char *name = (const char *)arg;
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, name);
    z_query_reply(query, z_query_keyexpr(query), z_move(payload), NULL);
}

typedef struct {
    char payload[16];
    atomic_uint replies;
    atomic_bool done;
} query_ctx_t;

static void query_reply_handler(z_loaned_reply_t *reply, void *arg) {
    query_ctx_t *ctx = (query_ctx_t *)arg;
    if (z_reply_is_ok(reply)) {
        z_owned_string_t value;
        z_bytes_to_string(z_sample_payload(z_reply_ok(reply)), &value);
        size_t len = z_string_len(z_loan(value));
        if (len >= sizeof(ctx->payload)) {
            len = sizeof(ctx->payload) - 1;
        }
        memcpy(ctx->payload, z_string_data(z_loan(value)), len);
        ctx->payload[len] = '\0';
        z_drop(z_move(value));
        atomic_fetch_add(&ctx->replies, 1);
    }
}

static void query_drop_handler(void *arg) { atomic_store(&((query_ctx_t *)arg)->done, true); }

static bool query_is_done(void *arg) { return atomic_load(&((query_ctx_t *)arg)->done); }

// Query keyexpr from s and check that exactly one reply with the expected payload is received
static void check_get(const z_loaned_session_t *s, const char *keyexpr, const char *expected) {
    query_ctx_t ctx;
    memset(ctx.payload, 0, sizeof(ctx.payload));
    atomic_store(&ctx.replies, 0);
    atomic_store(&ctx.done, false);
    z_view_keyexpr_t ke;
    assert_ok(z_view_keyexpr_from_str(&ke, keyexpr));
    z_owned_closure_reply_t cb;
    z_closure(&cb, query_reply_handler, query_drop_handler, &ctx);
    z_get_options_t opts;
    z_get_options_default(&opts);
    opts.timeout_ms = 2000;
    assert_ok(z_get(s, z_loan(ke), "", z_move(cb), &opts));
    assert(wait_until(query_is_done, &ctx, WAIT_TIMEOUT_MS));
    printf("  get on '%s': %u replies ('%s')\n", keyexpr, atomic_load(&ctx.replies), ctx.payload);
    assert(atomic_load(&ctx.replies) == 1);
    assert(strcmp(ctx.payload, expected) == 0);
}

typedef struct {
    const z_loaned_querier_t *querier;
    bool expected;
} matching_cond_t;

static bool querier_matching_is(void *arg) {
    matching_cond_t *c = (matching_cond_t *)arg;
    z_matching_status_t status;
    assert_ok(z_querier_get_matching_status(c->querier, &status));
    return status.matching == c->expected;
}

static void wait_querier_matching(const z_loaned_querier_t *querier, bool expected) {
    matching_cond_t c = {.querier = querier, .expected = expected};
    assert(wait_until(querier_matching_is, &c, WAIT_TIMEOUT_MS));
}

/*------------------ Tests ------------------*/

// Scenarios 1 to 3: liveliness tokens with the same id declared by two peers
static void test_tokens_same_id(uint16_t port) {
    printf("test_tokens_same_id (port %u)\n", (unsigned)port);
    z_owned_session_t h, a, b;
    open_listener(&h, port);
    open_connector(&a, port);
    open_connector(&b, port);
    wait_peers(z_loan(h), 2);

    // A and B declare a subscriber to check that data from H reaches both of them
    atomic_uint data_a = 0, data_b = 0;
    z_view_keyexpr_t data_ke;
    assert_ok(z_view_keyexpr_from_str(&data_ke, DATA_KE));
    z_owned_closure_sample_t sub_cb_a, sub_cb_b;
    z_closure(&sub_cb_a, count_sample, NULL, &data_a);
    z_closure(&sub_cb_b, count_sample, NULL, &data_b);
    assert_ok(z_declare_background_subscriber(z_loan(a), z_loan(data_ke), z_move(sub_cb_a), NULL));
    assert_ok(z_declare_background_subscriber(z_loan(b), z_loan(data_ke), z_move(sub_cb_b), NULL));

    // A and B declare a token: their ids are the same
    z_view_keyexpr_t ke_a, ke_b, ke_all;
    assert_ok(z_view_keyexpr_from_str(&ke_a, TOKEN_A));
    assert_ok(z_view_keyexpr_from_str(&ke_b, TOKEN_B));
    assert_ok(z_view_keyexpr_from_str(&ke_all, TOKEN_ALL));
    z_owned_liveliness_token_t tok_a, tok_b;
    assert_ok(z_liveliness_declare_token(z_loan(a), &tok_a, z_loan(ke_a), NULL));
    assert_ok(z_liveliness_declare_token(z_loan(b), &tok_b, z_loan(ke_b), NULL));
    assert(z_loan(tok_a)->_id == z_loan(tok_b)->_id);

    // 1. H keeps both connections and knows both tokens
    get_cond_t two_tokens = {.s = z_loan(h), .expected = 2};
    assert(wait_until(get_returns, &two_tokens, WAIT_TIMEOUT_MS));
    z_sleep_ms(200);
    assert(peers_count(z_loan(h)) == 2);
    get_ctx_t get;
    liveliness_get(z_loan(h), TOKEN_ALL, &get);
    assert(atomic_load(&get.total) == 2 && atomic_load(&get.a) == 1 && atomic_load(&get.b) == 1);

    // Data from H still reaches both peers
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "data");
    assert_ok(z_put(z_loan(h), z_loan(data_ke), z_move(payload), NULL));
    assert(wait_until(atomic_is_one, &data_a, WAIT_TIMEOUT_MS));
    assert(wait_until(atomic_is_one, &data_b, WAIT_TIMEOUT_MS));

    // A liveliness subscriber with history on H sees both tokens
    token_events_t ev;
    atomic_store(&ev.put_a, 0);
    atomic_store(&ev.put_b, 0);
    atomic_store(&ev.del_a, 0);
    atomic_store(&ev.del_b, 0);
    z_owned_closure_sample_t ev_cb;
    z_closure(&ev_cb, token_events_handler, NULL, &ev);
    z_liveliness_subscriber_options_t sub_opts;
    z_liveliness_subscriber_options_default(&sub_opts);
    sub_opts.history = true;
    z_owned_subscriber_t lsub;
    assert_ok(z_liveliness_declare_subscriber(z_loan(h), &lsub, z_loan(ke_all), z_move(ev_cb), &sub_opts));
    assert(wait_until(atomic_is_one, &ev.put_a, WAIT_TIMEOUT_MS));
    assert(wait_until(atomic_is_one, &ev.put_b, WAIT_TIMEOUT_MS));

    // 2. A undeclares its token: DELETE for A's key only, B's token is still alive
    assert_ok(z_liveliness_undeclare_token(z_move(tok_a)));
    assert(wait_until(atomic_is_one, &ev.del_a, WAIT_TIMEOUT_MS));
    z_sleep_ms(200);
    assert(atomic_load(&ev.del_b) == 0);
    assert(peers_count(z_loan(h)) == 2);
    liveliness_get(z_loan(h), TOKEN_ALL, &get);
    assert(atomic_load(&get.total) == 1 && atomic_load(&get.b) == 1);

    // 5. Liveliness get without matching token completes
    liveliness_get(z_loan(h), "test/peerdecl/nothing/**", &get);
    assert(atomic_load(&get.total) == 0);

    // 3. B's session closes: H drops B's token
    z_drop(z_move(b));
    z_drop(z_move(tok_b));  // session already closed
    assert(wait_until(atomic_is_one, &ev.del_b, WAIT_TIMEOUT_MS));
    wait_peers(z_loan(h), 1);
    liveliness_get(z_loan(h), TOKEN_ALL, &get);
    assert(atomic_load(&get.total) == 0);
    assert(atomic_load(&ev.del_a) == 1 && atomic_load(&ev.del_b) == 1);

    z_drop(z_move(lsub));
    z_drop(z_move(a));
    z_drop(z_move(h));
}

// Scenario 3 bis: a peer disconnecting without undeclaring its token
static void test_token_dropped_on_disconnect(uint16_t port) {
    printf("test_token_dropped_on_disconnect (port %u)\n", (unsigned)port);
    z_owned_session_t h, a, b;
    open_listener(&h, port);
    open_connector(&a, port);
    open_connector(&b, port);
    wait_peers(z_loan(h), 2);

    token_events_t ev;
    atomic_store(&ev.put_a, 0);
    atomic_store(&ev.put_b, 0);
    atomic_store(&ev.del_a, 0);
    atomic_store(&ev.del_b, 0);
    z_view_keyexpr_t ke_a, ke_b, ke_all;
    assert_ok(z_view_keyexpr_from_str(&ke_a, TOKEN_A));
    assert_ok(z_view_keyexpr_from_str(&ke_b, TOKEN_B));
    assert_ok(z_view_keyexpr_from_str(&ke_all, TOKEN_ALL));
    z_owned_closure_sample_t ev_cb;
    z_closure(&ev_cb, token_events_handler, NULL, &ev);
    z_owned_subscriber_t lsub;
    assert_ok(z_liveliness_declare_subscriber(z_loan(h), &lsub, z_loan(ke_all), z_move(ev_cb), NULL));

    z_owned_liveliness_token_t tok_a, tok_b;
    assert_ok(z_liveliness_declare_token(z_loan(a), &tok_a, z_loan(ke_a), NULL));
    assert_ok(z_liveliness_declare_token(z_loan(b), &tok_b, z_loan(ke_b), NULL));
    assert(wait_until(atomic_is_one, &ev.put_a, WAIT_TIMEOUT_MS));
    assert(wait_until(atomic_is_one, &ev.put_b, WAIT_TIMEOUT_MS));

    // Close B while its token is still declared
    z_drop(z_move(b));
    assert(wait_until(atomic_is_one, &ev.del_b, WAIT_TIMEOUT_MS));
    wait_peers(z_loan(h), 1);
    z_sleep_ms(200);
    assert(atomic_load(&ev.del_a) == 0);
    get_ctx_t get;
    liveliness_get(z_loan(h), TOKEN_ALL, &get);
    assert(atomic_load(&get.total) == 1 && atomic_load(&get.a) == 1);

    z_drop(z_move(tok_b));  // session already closed
    z_drop(z_move(lsub));
    z_drop(z_move(tok_a));
    z_drop(z_move(a));
    z_drop(z_move(h));
}

// Scenario 4: queryables with the same id declared by two peers
static void test_queryables_same_id(uint16_t port) {
    printf("test_queryables_same_id (port %u)\n", (unsigned)port);
    z_owned_session_t h, a, b;
    open_listener(&h, port);
    open_connector(&a, port);
    open_connector(&b, port);
    wait_peers(z_loan(h), 2);

    z_view_keyexpr_t ke_a, ke_b;
    assert_ok(z_view_keyexpr_from_str(&ke_a, QBL_A));
    assert_ok(z_view_keyexpr_from_str(&ke_b, QBL_B));
    z_owned_closure_query_t cb_a, cb_b;
    z_closure(&cb_a, reply_with_node_name, NULL, (void *)"A");
    z_closure(&cb_b, reply_with_node_name, NULL, (void *)"B");
    z_owned_queryable_t qbl_a, qbl_b;
    assert_ok(z_declare_queryable(z_loan(a), &qbl_a, z_loan(ke_a), z_move(cb_a), NULL));
    assert_ok(z_declare_queryable(z_loan(b), &qbl_b, z_loan(ke_b), z_move(cb_b), NULL));
    assert(z_loan(qbl_a)->_entity_id == z_loan(qbl_b)->_entity_id);

    // Queriers on H track the queryables of each peer
    z_owned_querier_t querier_a, querier_b;
    assert_ok(z_declare_querier(z_loan(h), &querier_a, z_loan(ke_a), NULL));
    assert_ok(z_declare_querier(z_loan(h), &querier_b, z_loan(ke_b), NULL));
    wait_querier_matching(z_loan(querier_a), true);
    wait_querier_matching(z_loan(querier_b), true);
    assert(peers_count(z_loan(h)) == 2);

    check_get(z_loan(h), QBL_A, "A");
    check_get(z_loan(h), QBL_B, "B");

    // Undeclaring A's queryable does not affect B's
    assert_ok(z_undeclare_queryable(z_move(qbl_a)));
    wait_querier_matching(z_loan(querier_a), false);
    z_sleep_ms(200);
    z_matching_status_t status;
    assert_ok(z_querier_get_matching_status(z_loan(querier_b), &status));
    assert(status.matching);
    check_get(z_loan(h), QBL_B, "B");

    // Undeclaring B's queryable is known to H (an unknown undeclaration would drop the connection)
    assert_ok(z_undeclare_queryable(z_move(qbl_b)));
    wait_querier_matching(z_loan(querier_b), false);
    z_sleep_ms(200);
    assert(peers_count(z_loan(h)) == 2);

    z_drop(z_move(querier_a));
    z_drop(z_move(querier_b));
    z_drop(z_move(b));
    z_drop(z_move(a));
    z_drop(z_move(h));
}

// Scenario 5: liveliness get without any peer
static void test_liveliness_get_no_peer(uint16_t port) {
    printf("test_liveliness_get_no_peer (port %u)\n", (unsigned)port);
    z_owned_session_t h;
    open_listener(&h, port);
    get_ctx_t get;
    liveliness_get(z_loan(h), TOKEN_ALL, &get);
    assert(atomic_load(&get.total) == 0);
    z_drop(z_move(h));
}

// Scenario 6: liveliness pending queries (used when the query is sent to a router) expire after their timeout
static void test_liveliness_pending_query_timeout(uint16_t port) {
    printf("test_liveliness_pending_query_timeout (port %u)\n", (unsigned)port);
    z_owned_session_t h;
    open_listener(&h, port);
    _z_session_t *zn = _Z_RC_IN_VAL(z_loan(h));

    get_ctx_t short_ctx, long_ctx;
    get_ctx_init(&short_ctx);
    get_ctx_init(&long_ctx);
    uint32_t long_id = 0;
    get_ctx_t *ctxs[2] = {&short_ctx, &long_ctx};
    uint64_t timeouts[2] = {100, 60000};
    for (int i = 0; i < 2; i++) {
        _z_session_mutex_lock(zn);
        _z_liveliness_pending_query_t *pq = _z_unsafe_liveliness_register_pending_query(zn);
        assert(pq != NULL);
        pq->_key = _z_keyexpr_null();
        pq->_callback = get_reply_handler;
        pq->_dropper = get_drop_handler;
        pq->_arg = ctxs[i];
        pq->_start_time = z_clock_now();
        pq->_timeout = timeouts[i];
#ifdef Z_FEATURE_UNSTABLE_API
        pq->_cancellation_data = _z_pending_query_cancellation_data_null();
#endif
        long_id = pq->_id;
        _z_session_mutex_unlock(zn);
    }

    // The periodic timeout task drops the expired query only
    assert(wait_until(get_is_done, &short_ctx, 3000));
    assert(!atomic_load(&long_ctx.done));
    assert(_z_liveliness_unregister_pending_query(zn, long_id) == _Z_RES_OK);
    assert(atomic_load(&long_ctx.done));

    // Explicit processing of the timeouts does not drop a non expired query
    get_ctx_init(&long_ctx);
    _z_session_mutex_lock(zn);
    _z_liveliness_pending_query_t *pq = _z_unsafe_liveliness_register_pending_query(zn);
    assert(pq != NULL);
    pq->_key = _z_keyexpr_null();
    pq->_callback = get_reply_handler;
    pq->_dropper = get_drop_handler;
    pq->_arg = &long_ctx;
    pq->_start_time = z_clock_now();
    pq->_timeout = 60000;
#ifdef Z_FEATURE_UNSTABLE_API
    pq->_cancellation_data = _z_pending_query_cancellation_data_null();
#endif
    _z_session_mutex_unlock(zn);
    _z_liveliness_pending_query_process_timeout(zn);
    assert(!atomic_load(&long_ctx.done));

    // Remaining pending queries are dropped with the session
    z_drop(z_move(h));
    assert(atomic_load(&long_ctx.done));
}

int main(void) {
    const char *port_env = getenv("Z_TEST_BASE_PORT");
    g_base_port = (port_env != NULL) ? (uint16_t)atoi(port_env) : (uint16_t)(20000 + (getpid() % 20000) * 2);
    // Distinct ports per test case
    test_tokens_same_id(g_base_port);
    test_token_dropped_on_disconnect((uint16_t)(g_base_port + 1));
    test_queryables_same_id((uint16_t)(g_base_port + 2));
    test_liveliness_get_no_peer((uint16_t)(g_base_port + 3));
    test_liveliness_pending_query_timeout((uint16_t)(g_base_port + 4));
    printf("All tests passed\n");
    return 0;
}

#else
int main(void) {
    printf(
        "Missing config token to build this test. This test requires: Z_FEATURE_MULTI_THREAD, "
        "Z_FEATURE_UNICAST_PEER, Z_FEATURE_LINK_TCP, Z_FEATURE_LIVELINESS, Z_FEATURE_SUBSCRIPTION, "
        "Z_FEATURE_PUBLICATION, Z_FEATURE_QUERY, Z_FEATURE_QUERYABLE, Z_FEATURE_INTEREST, Z_FEATURE_MATCHING, and "
        "no Z_FEATURE_LOCAL_SUBSCRIBER / Z_FEATURE_LOCAL_QUERYABLE\n");
    return 0;
}
#endif
