// This file Copyright © Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring> /* for strcspn() */
#include <ctime>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/listener.h>

#include <fmt/chrono.h>
#include <fmt/format.h>

#include <libdeflate.h>

#include "libtransmission/crypto-utils.h" /* tr_ssha1_matches() */
#include "libtransmission/error.h"
#include "libtransmission/file-utils.h"
#include "libtransmission/inout.h"
#include "libtransmission/log.h"
#include "libtransmission/net.h"
#include "libtransmission/platform.h" /* tr_getWebClientDir() */
#include "libtransmission/quark.h"
#include "libtransmission/rpc-server.h"
#include "libtransmission/rpcimpl.h"
#include "libtransmission/session.h"
#include "libtransmission/string-utils.h"
#include "libtransmission/timer.h"
#include "libtransmission/torrent.h"
#include "libtransmission/torrents.h"
#include "libtransmission/tr-strbuf.h"
#include "libtransmission/types.h"
#include "libtransmission/variant.h"
#include "libtransmission/web-utils.h"

struct evbuffer;

/* session_id is used to make cross-site request forgery attacks difficult.
 * Don't disable this feature unless you really know what you're doing!
 * https://en.wikipedia.org/wiki/Cross-site_request_forgery
 * https://shiflett.org/articles/cross-site-request-forgeries
 * http://www.webappsec.org/lists/websecurity/archive/2008-04/msg00037.html */
#define REQUIRE_SESSION_ID

#define MY_REALM "Transmission"

using namespace std::literals;

namespace
{
auto constexpr TrUnixSocketPrefix = "unix:"sv;

/* The maximum size of a unix socket path is defined per-platform based on sockaddr_un.sun_path.
 * On Windows the fallback is the length of an ipv6 address. Subtracting one at the end is for
 * double counting null terminators from sun_path and TrUnixSocketPrefix. */
#ifdef _WIN32
auto inline constexpr TrUnixAddrStrLen = size_t{ INET6_ADDRSTRLEN };
#else
auto inline constexpr TrUnixAddrStrLen = size_t{ sizeof(std::declval<struct sockaddr_un>().sun_path) +
                                                 std::size(TrUnixSocketPrefix) };
#endif

enum tr_rpc_address_type : uint8_t
{
    TR_RPC_INET_ADDR,
    TR_RPC_UNIX_ADDR
};

class tr_unix_addr
{
public:
    [[nodiscard]] std::string to_string() const
    {
        return std::empty(unix_socket_path_) ? std::string(TrUnixSocketPrefix) : unix_socket_path_;
    }

    [[nodiscard]] bool from_string(std::string_view src)
    {
        if (!tr_strv_starts_with(src, TrUnixSocketPrefix))
        {
            return false;
        }

        if (std::size(src) >= TrUnixAddrStrLen)
        {
            tr_logAddError(
                fmt::format(
                    fmt::runtime(_("Unix socket path must be fewer than {count} characters (including '{prefix}' prefix)")),
                    fmt::arg("count", TrUnixAddrStrLen - 1),
                    fmt::arg("prefix", TrUnixSocketPrefix)));
            return false;
        }
        unix_socket_path_ = src;
        return true;
    }

private:
    std::string unix_socket_path_;
};
} // namespace

class tr_rpc_address
{
public:
    tr_rpc_address()
        : inet_addr_{ tr_address::any(TR_AF_INET) }
    {
    }

    [[nodiscard]] constexpr auto is_unix_addr() const noexcept
    {
        return type_ == TR_RPC_UNIX_ADDR;
    }

    [[nodiscard]] constexpr auto is_inet_addr() const noexcept
    {
        return type_ == TR_RPC_INET_ADDR;
    }

    bool from_string(std::string_view src)
    {
        if (auto address = tr_address::from_string(src); address.has_value())
        {
            type_ = TR_RPC_INET_ADDR;
            inet_addr_ = address.value();
            return true;
        }

        if (unix_addr_.from_string(src))
        {
            type_ = TR_RPC_UNIX_ADDR;
            return true;
        }

        return false;
    }

    [[nodiscard]] std::string to_string(tr_port port = {}) const
    {
        if (type_ == TR_RPC_UNIX_ADDR)
        {
            return unix_addr_.to_string();
        }

        if (std::empty(port))
        {
            return inet_addr_.display_name();
        }
        return tr_socket_address::display_name(inet_addr_, port);
    }

private:
    tr_rpc_address_type type_ = TR_RPC_INET_ADDR;
    struct tr_address inet_addr_;
    class tr_unix_addr unix_addr_;
};

namespace
{
int constexpr DeflateLevel = 6; // medium / default

// ---

void send_simple_response(struct evhttp_request* req, int code, char const* text = nullptr)
{
    char const* code_text = tr_webGetResponseStr(code);
    struct evbuffer* body = evbuffer_new();

    evbuffer_add_printf(body, "<h1>%d: %s</h1>", code, code_text);

    if (text != nullptr)
    {
        evbuffer_add_printf(body, "%s", text);
    }

    evhttp_send_reply(req, code, code_text, body);

    evbuffer_free(body);
}

// ---

[[nodiscard]] constexpr char const* mimetype_guess(std::string_view path)
{
    // MIME types for serving web client and torrent content files
    auto constexpr Types = std::array<std::pair<std::string_view, char const*>, 30>{ {
        { ".aac"sv, "audio/aac" },
        { ".avi"sv, "video/x-msvideo" },
        { ".css"sv, "text/css" },
        { ".flac"sv, "audio/flac" },
        { ".gif"sv, "image/gif" },
        { ".htm"sv, "text/html" },
        { ".html"sv, "text/html" },
        { ".ico"sv, "image/vnd.microsoft.icon" },
        { ".jpeg"sv, "image/jpeg" },
        { ".jpg"sv, "image/jpeg" },
        { ".js"sv, "application/javascript" },
        { ".json"sv, "application/json" },
        { ".m4a"sv, "audio/mp4" },
        { ".m4v"sv, "video/mp4" },
        { ".mkv"sv, "video/x-matroska" },
        { ".mov"sv, "video/quicktime" },
        { ".mp3"sv, "audio/mpeg" },
        { ".mp4"sv, "video/mp4" },
        { ".mpeg"sv, "video/mpeg" },
        { ".ogg"sv, "audio/ogg" },
        { ".ogv"sv, "video/ogg" },
        { ".opus"sv, "audio/opus" },
        { ".png"sv, "image/png" },
        { ".svg"sv, "image/svg+xml" },
        { ".ts"sv, "video/mp2t" },
        { ".txt"sv, "text/plain" },
        { ".wav"sv, "audio/wav" },
        { ".weba"sv, "audio/webm" },
        { ".webm"sv, "video/webm" },
        { ".webp"sv, "image/webp" },
    } };

    for (auto const& [suffix, mime_type] : Types)
    {
        if (tr_strv_ends_with(path, suffix))
        {
            return mime_type;
        }
    }

    return "application/octet-stream";
}

[[nodiscard]] evbuffer* make_response(struct evhttp_request* req, tr_rpc_server const* server, std::string_view content)
{
    auto* const out = evbuffer_new();
    auto const* const input_headers = evhttp_request_get_input_headers(req);
    auto* const output_headers = evhttp_request_get_output_headers(req);

    char const* encoding = evhttp_find_header(input_headers, "Accept-Encoding");

    if (bool const do_compress = encoding != nullptr && tr_strv_contains(encoding, "gzip"sv); !do_compress)
    {
        evbuffer_add(out, std::data(content), std::size(content));
    }
    else
    {
        auto const max_compressed_len = libdeflate_deflate_compress_bound(server->compressor.get(), std::size(content));

        auto iov = evbuffer_iovec{};
        evbuffer_reserve_space(out, std::max(std::size(content), max_compressed_len), &iov, 1);

        auto const compressed_len = libdeflate_gzip_compress(
            server->compressor.get(),
            std::data(content),
            std::size(content),
            iov.iov_base,
            iov.iov_len);
        if (0 < compressed_len && compressed_len < std::size(content))
        {
            iov.iov_len = compressed_len;
            evhttp_add_header(output_headers, "Content-Encoding", "gzip");
        }
        else
        {
            std::ranges::copy(content, static_cast<char*>(iov.iov_base));
            iov.iov_len = std::size(content);
        }

        evbuffer_commit_space(out, &iov, 1);
    }

    return out;
}

void add_time_header(struct evkeyvalq* headers, char const* key, time_t now)
{
    // RFC 2616 says this must follow RFC 1123's date format, so use gmtime instead of localtime
    evhttp_add_header(headers, key, fmt::format("{:%a %b %d %T %Y%n}", fmt::gmtime(now)).c_str());
}

void serve_file(struct evhttp_request* req, tr_rpc_server const* server, std::string_view filename)
{
    auto* const output_headers = evhttp_request_get_output_headers(req);
    if (auto const cmd = evhttp_request_get_command(req); cmd != EVHTTP_REQ_GET)
    {
        evhttp_add_header(output_headers, "Allow", "GET");
        send_simple_response(req, HTTP_BADMETHOD);
        return;
    }

    auto content = std::vector<char>{};

    if (auto error = tr_error{}; !tr_file_read(filename, content, &error))
    {
        send_simple_response(req, HTTP_NOTFOUND, fmt::format("{} ({})", filename, error.message()).c_str());
        return;
    }

    auto const now = tr_time();
    add_time_header(output_headers, "Date", now);
    add_time_header(output_headers, "Expires", now + (24 * 60 * 60));
    evhttp_add_header(output_headers, "Content-Type", mimetype_guess(filename));

    auto* const response = make_response(req, server, std::string_view{ std::data(content), std::size(content) });
    evhttp_send_reply(req, HTTP_OK, "OK", response);
    evbuffer_free(response);
}

void handle_web_client(struct evhttp_request* req, tr_rpc_server const* server)
{
    if (std::empty(server->web_client_dir_))
    {
        send_simple_response(
            req,
            HTTP_NOTFOUND,
            "<p>Couldn't find Transmission's web interface files!</p>"
            "<p>Users: to tell Transmission where to look, "
            "set the TRANSMISSION_WEB_HOME environment "
            "variable to the folder where the web interface's "
            "index.html is located.</p>"
            "<p>Package Builders: to set a custom default at compile time, "
            "#define PACKAGE_DATA_DIR in libtransmission/platform.c "
            "or tweak tr_getClutchDir() by hand.</p>");
        return;
    }

    // convert the URL path component into a filesystem path, e.g.
    // "/transmission/web/images/favicon.png" ->
    // "/usr/share/transmission/web/images/favicon.png")
    auto subpath = std::string_view{ evhttp_request_get_uri(req) };

    // remove the web base path eg "/transmission/web/"
    {
        auto const& base_path = server->url();
        static auto constexpr Web = TrHttpServerWebRelativePath;
        subpath = subpath.substr(std::size(base_path) + std::size(Web));
    }

    // remove any trailing query / fragment
    subpath = subpath.substr(0, subpath.find_first_of("?#"sv));

    // if the query is empty, use the default
    if (std::empty(subpath))
    {
        static auto constexpr DefaultPage = "index.html"sv;
        subpath = DefaultPage;
    }

    if (tr_strv_contains(subpath, ".."sv))
    {
        if (auto* const con = evhttp_request_get_connection(req); con != nullptr)
        {
#if LIBEVENT_VERSION_NUMBER >= 0x02020001
            char const* remote_host = nullptr;
#else
            char* remote_host = nullptr;
#endif
            auto remote_port = ev_uint16_t{};
            evhttp_connection_get_peer(con, &remote_host, &remote_port);
            tr_logAddWarn(
                fmt::format(
                    fmt::runtime(_("Rejected request from {host} (possible directory traversal attack)")),
                    fmt::arg("host", remote_host)));
        }
        send_simple_response(req, HTTP_NOTFOUND);
    }
    else
    {
        serve_file(req, server, tr_pathbuf{ server->web_client_dir_, '/', subpath });
    }
}

// ---

// Parse an HTTP Range header value like "bytes=START-END" into byte offsets.
// Returns true on success, populating range_begin and range_end (inclusive).
[[nodiscard]] bool parse_range_header(char const* range_str, uint64_t file_size, uint64_t& range_begin, uint64_t& range_end)
{
    if (range_str == nullptr)
    {
        return false;
    }

    auto range = std::string_view{ range_str };
    static auto constexpr Prefix = "bytes="sv;
    if (!tr_strv_starts_with(range, Prefix))
    {
        return false;
    }
    range.remove_prefix(std::size(Prefix));

    auto const dash = range.find('-');
    if (dash == std::string_view::npos)
    {
        return false;
    }

    auto const start_str = range.substr(0, dash);
    auto const end_str = range.substr(dash + 1);

    if (std::empty(start_str))
    {
        // suffix range like "bytes=-500" (last 500 bytes)
        auto suffix_len = uint64_t{};
        auto const [ptr, ec] = std::from_chars(std::data(end_str), std::data(end_str) + std::size(end_str), suffix_len);
        if (ec != std::errc{} || suffix_len == 0 || suffix_len > file_size)
        {
            return false;
        }
        range_begin = file_size - suffix_len;
        range_end = file_size - 1;
    }
    else
    {
        auto const [ptr1, ec1] = std::from_chars(
            std::data(start_str),
            std::data(start_str) + std::size(start_str),
            range_begin);
        if (ec1 != std::errc{})
        {
            return false;
        }

        if (std::empty(end_str))
        {
            range_end = file_size - 1;
        }
        else
        {
            auto const [ptr2, ec2] = std::from_chars(std::data(end_str), std::data(end_str) + std::size(end_str), range_end);
            if (ec2 != std::errc{})
            {
                return false;
            }
        }
    }

    if (range_begin > range_end || range_begin >= file_size)
    {
        return false;
    }

    // Clamp to file size
    range_end = std::min(range_end, file_size - 1);
    return true;
}

// Compute the absolute byte offset where a file starts within the torrent.
[[nodiscard]] uint64_t file_byte_offset(tr_torrent const& tor, tr_file_index_t file_index)
{
    uint64_t offset = 0;
    for (tr_file_index_t i = 0; i < file_index; ++i)
    {
        offset += tor.file_size(i);
    }
    return offset;
}

// Find which file in the torrent matches the given subpath.
// Returns the file index or nullopt if not found.
[[nodiscard]] std::optional<tr_file_index_t> find_file_in_torrent(tr_torrent const& tor, std::string_view subpath)
{
    for (tr_file_index_t i = 0, n = tor.file_count(); i < n; ++i)
    {
        if (tor.file_subpath(i) == subpath)
        {
            return i;
        }
    }
    return std::nullopt;
}

// Set per-piece priorities for torrent content serving:
// - Mark the file as wanted (low priority) if it was previously unwanted
// - Set pieces in the requested range to HIGH priority
// - Set pieces in the lookahead range (same length, immediately after) to NORMAL priority
void prioritize_pieces_for_request(tr_torrent* tor, tr_file_index_t file_index, uint64_t range_begin, uint64_t range_end)
{
    // Mark file as wanted if it was not already, with low priority
    if (!tor->file_is_wanted(file_index))
    {
        tor->set_files_wanted(&file_index, 1, true);
        tor->set_file_priorities(&file_index, 1, TR_PRI_LOW);
    }

    auto const file_offset_in_torrent = file_byte_offset(*tor, file_index);
    auto const piece_file_span = tor->piece_span_for_file(file_index);

    // Absolute byte positions within the torrent
    auto const abs_begin = file_offset_in_torrent + range_begin;
    auto const abs_end = file_offset_in_torrent + range_end;
    auto const range_length = range_end - range_begin + 1;

    // Find piece range covering the requested bytes
    auto const first_piece = tor->byte_loc(abs_begin).piece;
    auto const last_piece = tor->byte_loc(abs_end).piece;

    // Set HIGH priority for pieces in the requested range
    for (auto piece = first_piece; piece <= last_piece; ++piece)
    {
        if (piece >= piece_file_span.begin && piece < piece_file_span.end)
        {
            tor->set_piece_priority(piece, TR_PRI_HIGH);
        }
    }

    // Lookahead: set NORMAL priority for pieces in the next range of equivalent length
    auto const lookahead_abs_begin = abs_end + 1;
    auto const lookahead_abs_end = abs_end + range_length;

    if (lookahead_abs_begin < tor->total_size())
    {
        auto const lookahead_first = tor->byte_loc(lookahead_abs_begin).piece;
        auto const clamped_end = std::min(lookahead_abs_end, tor->total_size() - 1);
        auto const lookahead_last = tor->byte_loc(clamped_end).piece;

        for (auto piece = lookahead_first; piece <= lookahead_last; ++piece)
        {
            if (piece >= piece_file_span.begin && piece < piece_file_span.end)
            {
                tor->set_piece_priority(piece, TR_PRI_NORMAL);
            }
        }
    }
}

// Context for a streaming torrent content response.
// Data is sent in bounded chunks as blocks become available,
// avoiding loading the entire range into memory.
struct torrent_content_request
{
    struct evhttp_request* req;
    tr_rpc_server* server;
    tr_torrent_id_t torrent_id;
    tr_file_index_t file_index;
    uint64_t file_size;
    uint64_t range_begin;
    uint64_t range_end;
    bool is_range_request;
    char const* mime_type = nullptr;
    std::unique_ptr<tr::Timer> poll_timer = {};
    int poll_count = 0;

    // Streaming state
    bool reply_started = false;
    uint64_t bytes_sent = 0; // bytes of the requested range sent so far
};

auto constexpr MaxPollCount = 600; // 60 seconds at 100ms intervals
auto constexpr PollIntervalMs = std::chrono::milliseconds{ 100 };
auto constexpr StreamChunkSize = uint64_t{ 256U * 1024U }; // max bytes per read/send pass

void stream_torrent_content(torrent_content_request* ctx);

// Called by libevent when a chunk has been fully flushed to the socket.
// This provides natural backpressure: we only send the next chunk after
// the previous one has been written, keeping at most one chunk buffered.
void on_chunk_flushed(struct evhttp_connection* /*evcon*/, void* arg)
{
    auto* ctx = static_cast<torrent_content_request*>(arg);
    stream_torrent_content(ctx);
}

// Begin the HTTP response (headers + start of chunked reply).
void start_torrent_reply(torrent_content_request* ctx)
{
    auto* const output_headers = evhttp_request_get_output_headers(ctx->req);
    evhttp_add_header(output_headers, "Content-Type", ctx->mime_type);
    evhttp_add_header(output_headers, "Accept-Ranges", "bytes");

    auto const length = ctx->range_end - ctx->range_begin + 1;
    evhttp_add_header(output_headers, "Content-Length", fmt::format("{}", length).c_str());

    if (ctx->is_range_request)
    {
        auto const content_range = fmt::format("bytes {}-{}/{}", ctx->range_begin, ctx->range_end, ctx->file_size);
        evhttp_add_header(output_headers, "Content-Range", content_range.c_str());
        evhttp_send_reply_start(ctx->req, 206, "Partial Content");
    }
    else
    {
        evhttp_send_reply_start(ctx->req, HTTP_OK, "OK");
    }

    ctx->reply_started = true;
}

// Stream one chunk of available blocks to the client, then wait for
// the flush callback before sending the next. This ensures at most
// one chunk (StreamChunkSize) is buffered in libevent at any time.
// If blocked on unavailable data, schedules a poll timer instead.
void stream_torrent_content(torrent_content_request* ctx)
{
    auto* const tor = ctx->server->session->torrents().get(ctx->torrent_id);
    if (tor == nullptr)
    {
        if (ctx->reply_started)
        {
            evhttp_send_reply_end(ctx->req);
        }
        else
        {
            send_simple_response(ctx->req, HTTP_NOTFOUND, "Torrent no longer available");
        }
        delete ctx;
        return;
    }

    auto const file_start = file_byte_offset(*tor, ctx->file_index);
    auto const total_length = ctx->range_end - ctx->range_begin + 1;

    // Send response headers on first entry
    if (!ctx->reply_started)
    {
        start_torrent_reply(ctx);
    }

    // All data sent?
    if (ctx->bytes_sent >= total_length)
    {
        evhttp_send_reply_end(ctx->req);
        delete ctx;
        return;
    }

    auto const current_abs = file_start + ctx->range_begin + ctx->bytes_sent;
    auto const remaining = total_length - ctx->bytes_sent;

    // Determine the block range for the next chunk (bounded by StreamChunkSize)
    auto const chunk_want = std::min(StreamChunkSize, remaining);
    auto const chunk_end_abs = current_abs + chunk_want - 1;

    auto const first_block = tor->byte_loc(current_abs).block;
    auto const last_block = tor->byte_loc(chunk_end_abs).block;

    // The first block we need must be available to make progress
    if (!tor->has_block(first_block))
    {
        // Data not yet downloaded — poll until it arrives
        ++ctx->poll_count;
        if (ctx->poll_count >= MaxPollCount)
        {
            evhttp_send_reply_end(ctx->req);
            delete ctx;
            return;
        }

        auto const next_byte_in_file = ctx->range_begin + ctx->bytes_sent;
        prioritize_pieces_for_request(tor, ctx->file_index, next_byte_in_file, ctx->range_end);

        ctx->poll_timer->start_single_shot(PollIntervalMs);
        return;
    }

    // Find the longest run of consecutive available blocks (up to chunk size)
    auto avail_end_block = first_block;
    for (auto b = first_block + 1; b <= last_block; ++b)
    {
        if (!tor->has_block(b))
        {
            break;
        }
        avail_end_block = b;
    }

    // Compute readable byte count, clamped to the requested range
    auto const avail_block_end_byte = static_cast<uint64_t>(tor->block_loc(avail_end_block).byte) +
        tor->block_size(avail_end_block);
    auto const readable_end_abs = std::min(avail_block_end_byte, file_start + ctx->range_end + 1);
    auto const readable_bytes = std::min(readable_end_abs - current_abs, remaining);

    // Read into a bounded buffer
    auto buf = std::vector<uint8_t>(readable_bytes);
    auto const loc = tor->byte_loc(current_abs);
    auto const err = tr_ioRead(*tor, loc, std::span<uint8_t>{ buf.data(), buf.size() });

    if (err != 0)
    {
        evhttp_send_reply_end(ctx->req);
        delete ctx;
        return;
    }

    ctx->bytes_sent += readable_bytes;
    ctx->poll_count = 0; // reset timeout on progress

    // Check if this is the final chunk
    if (ctx->bytes_sent >= total_length)
    {
        // Last chunk: send without callback, then end the reply
        auto* const evb = evbuffer_new();
        evbuffer_add(evb, buf.data(), buf.size());
        evhttp_send_reply_chunk(ctx->req, evb);
        evbuffer_free(evb);

        evhttp_send_reply_end(ctx->req);
        delete ctx;
        return;
    }

    // Send this chunk and wait for the flush callback before sending more.
    // This is the backpressure mechanism: on_chunk_flushed() is called only
    // after libevent has fully drained this chunk to the socket, so we never
    // queue more than one chunk in the output buffer at a time.
    auto* const evb = evbuffer_new();
    evbuffer_add(evb, buf.data(), buf.size());
    evhttp_send_reply_chunk_with_cb(ctx->req, evb, on_chunk_flushed, ctx);
    evbuffer_free(evb);
}

void handle_torrent_content(struct evhttp_request* req, tr_rpc_server* server, std::string_view subpath)
{
    auto* const output_headers = evhttp_request_get_output_headers(req);

    if (auto const cmd = evhttp_request_get_command(req); cmd != EVHTTP_REQ_GET)
    {
        evhttp_add_header(output_headers, "Allow", "GET");
        send_simple_response(req, HTTP_BADMETHOD);
        return;
    }

    // Reject directory traversal
    if (tr_strv_contains(subpath, ".."sv))
    {
        send_simple_response(req, HTTP_NOTFOUND);
        return;
    }

    // Remove query/fragment
    subpath = subpath.substr(0, subpath.find_first_of("?#"sv));

    // Parse: <infohash>/<filepath>
    auto const slash = subpath.find('/');
    if (slash == std::string_view::npos || slash == 0)
    {
        send_simple_response(req, HTTP_NOTFOUND, "Expected /transmission/torrents/&lt;infohash&gt;/&lt;filepath&gt;");
        return;
    }

    auto const hash_str = subpath.substr(0, slash);
    auto const file_path = subpath.substr(slash + 1);

    if (std::empty(file_path))
    {
        send_simple_response(req, HTTP_NOTFOUND, "No file path specified");
        return;
    }

    // Look up the torrent by info hash
    auto const digest = tr_sha1_from_string(hash_str);
    if (!digest.has_value())
    {
        send_simple_response(req, HTTP_NOTFOUND, "Invalid info hash");
        return;
    }

    auto* const tor = server->session->torrents().get(digest.value());
    if (tor == nullptr)
    {
        send_simple_response(req, HTTP_NOTFOUND, "Torrent not found");
        return;
    }

    if (!tor->has_metainfo())
    {
        send_simple_response(req, HTTP_NOTFOUND, "Torrent metadata not yet available");
        return;
    }

    // Find the file
    auto const file_index = find_file_in_torrent(*tor, file_path);
    if (!file_index.has_value())
    {
        send_simple_response(req, HTTP_NOTFOUND, "File not found in torrent");
        return;
    }

    auto const fi = file_index.value();
    auto const file_size = tor->file_size(fi);

    if (file_size == 0)
    {
        evhttp_add_header(output_headers, "Content-Length", "0");
        evhttp_add_header(output_headers, "Content-Type", mimetype_guess(file_path));
        evhttp_add_header(output_headers, "Accept-Ranges", "bytes");
        evhttp_send_reply(req, HTTP_OK, "OK", nullptr);
        return;
    }

    // Parse Range header
    auto const* const input_headers = evhttp_request_get_input_headers(req);
    auto const* const range_hdr = evhttp_find_header(input_headers, "Range");

    auto range_begin = uint64_t{ 0 };
    auto range_end = file_size - 1;
    bool const is_range_request = parse_range_header(range_hdr, file_size, range_begin, range_end);

    if (range_hdr != nullptr && !is_range_request)
    {
        // Range header present but invalid
        auto const content_range = fmt::format("bytes */{}", file_size);
        evhttp_add_header(output_headers, "Content-Range", content_range.c_str());
        send_simple_response(req, 416); // Range Not Satisfiable
        return;
    }

    // Prioritize the pieces we need
    prioritize_pieces_for_request(tor, fi, range_begin, range_end);

    auto const* const mime = mimetype_guess(file_path);

    // Create a streaming context — data is sent in bounded chunks
    // as blocks become available, never loading the full range into memory.
    // poll_timer is set separately since its lambda captures ctx.
    auto* ctx = new torrent_content_request{
        .req = req,
        .server = server,
        .torrent_id = tor->id(),
        .file_index = fi,
        .file_size = file_size,
        .range_begin = range_begin,
        .range_end = range_end,
        .is_range_request = is_range_request,
        .mime_type = mime,
    };
    ctx->poll_timer = server->session->timerMaker().create([ctx]() { stream_torrent_content(ctx); });

    // Start streaming immediately — will send available blocks
    // and poll for any that are not yet downloaded.
    stream_torrent_content(ctx);
}

void handle_rpc_from_json(struct evhttp_request* req, tr_rpc_server* server, std::string_view json)
{
    tr_rpc_request_exec(
        server->session,
        json,
        // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
        [req, server](tr_variant&& content)
        {
            if (!content.has_value())
            {
                evhttp_send_reply(req, HTTP_NOCONTENT, "OK", nullptr);
                return;
            }

            auto* const output_headers = evhttp_request_get_output_headers(req);
            auto* const response = make_response(req, server, tr_variant_serde::json().compact().to_string(content));
            evhttp_add_header(output_headers, "Content-Type", "application/json; charset=UTF-8");
            evhttp_send_reply(req, HTTP_OK, "OK", response);
            evbuffer_free(response);
        });
}

void handle_rpc(struct evhttp_request* req, tr_rpc_server* server)
{
    if (auto const cmd = evhttp_request_get_command(req); cmd == EVHTTP_REQ_POST)
    {
        auto* const input_buffer = evhttp_request_get_input_buffer(req);
        auto json = std::string_view{ reinterpret_cast<char const*>(evbuffer_pullup(input_buffer, -1)),
                                      evbuffer_get_length(input_buffer) };
        handle_rpc_from_json(req, server, json);
        return;
    }

    send_simple_response(req, HTTP_BADMETHOD);
}

bool is_address_allowed(tr_rpc_server const* server, char const* address)
{
    if (!server->is_whitelist_enabled())
    {
        return true;
    }

    // Convert IPv4-mapped address to IPv4 address
    // so that it can match with IPv4 whitelist entries
    auto native = std::string{};
    if (auto ipv4_mapped = tr_address::from_string(address); ipv4_mapped)
    {
        if (auto addr = ipv4_mapped->from_ipv4_mapped(); addr)
        {
            native = addr->display_name();
        }
    }
    auto const* const addr = std::empty(native) ? address : native.c_str();

    auto const& src = server->whitelist_;
    return std::ranges::any_of(src, [&addr](auto const& s) { return tr_wildmat(addr, s.c_str()); });
}

bool isIPAddressWithOptionalPort(char const* host)
{
    auto address = sockaddr_storage{};
    int address_len = sizeof(address);

    /* TODO: move to net.{c,h} */
    return evutil_parse_sockaddr_port(host, reinterpret_cast<sockaddr*>(&address), &address_len) != -1;
}

bool isHostnameAllowed(tr_rpc_server const* server, evhttp_request* const req)
{
    /* If password auth is enabled, any hostname is permitted. */
    if (server->is_password_enabled())
    {
        return true;
    }

    /* If whitelist is disabled, no restrictions. */
    if (!server->settings_.is_host_whitelist_enabled)
    {
        return true;
    }

    auto const* const host = evhttp_request_get_host(req);

    /* No host header, invalid request. */
    if (host == nullptr)
    {
        return false;
    }

    /* IP address is always acceptable. */
    if (isIPAddressWithOptionalPort(host))
    {
        return true;
    }

    /* Host header might include the port. */
    auto const hostname = std::string_view{ host, strcspn(host, ":") };

    /* localhost is always acceptable. */
    if (hostname == "localhost"sv || hostname == "localhost."sv)
    {
        return true;
    }

    auto const& src = server->host_whitelist_;
    auto const hostname_sz = tr_urlbuf{ hostname };
    return std::ranges::any_of(src, [&hostname_sz](auto const& str) { return tr_wildmat(hostname_sz, str.c_str()); });
}

bool test_session_id(tr_rpc_server const* server, evhttp_request* const req)
{
    auto const* const input_headers = evhttp_request_get_input_headers(req);
    char const* const session_id = evhttp_find_header(input_headers, std::data(TrRpcSessionIdHeader));
    return session_id != nullptr && server->session->sessionId() == session_id;
}

bool is_authorized(tr_rpc_server const* server, char const* auth_header)
{
    if (!server->is_password_enabled())
    {
        return true;
    }

    // https://datatracker.ietf.org/doc/html/rfc7617
    // `Basic ${base64(username)}:${base64(password)}`

    auto constexpr Prefix = "Basic "sv;
    auto auth = std::string_view{ auth_header != nullptr ? auth_header : "" };
    if (!tr_strv_starts_with(auth, Prefix))
    {
        return false;
    }

    auth.remove_prefix(std::size(Prefix));
    auto const decoded_str = tr_base64_decode(auth);
    auto decoded = std::string_view{ decoded_str };
    auto const username = tr_strv_sep(&decoded, ':');
    auto const password = decoded;
    return server->username() == username && tr_ssha1_matches(server->settings().salted_password, password);
}

void handle_request(struct evhttp_request* req, void* arg)
{
    auto constexpr HttpErrorUnauthorized = 401;
    auto constexpr HttpErrorForbidden = 403;

    if (req == nullptr)
    {
        return;
    }

    auto* const con = evhttp_request_get_connection(req);
    if (con == nullptr)
    {
        return;
    }

    auto* server = static_cast<tr_rpc_server*>(arg);

#if LIBEVENT_VERSION_NUMBER >= 0x02020001
    char const* remote_host = nullptr;
#else
    char* remote_host = nullptr;
#endif
    auto remote_port = ev_uint16_t{};
    evhttp_connection_get_peer(con, &remote_host, &remote_port);

    auto* const output_headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(output_headers, "Server", MY_REALM);

    if (server->is_anti_brute_force_enabled() && server->login_attempts_ >= server->settings().anti_brute_force_limit)
    {
        tr_logAddWarn(
            fmt::format(
                fmt::runtime(_("Rejected request from {host} (brute force protection active)")),
                fmt::arg("host", remote_host)));
        send_simple_response(req, HttpErrorForbidden);
        return;
    }

    if (!is_address_allowed(server, remote_host))
    {
        tr_logAddWarn(
            fmt::format(fmt::runtime(_("Rejected request from {host} (IP not whitelisted)")), fmt::arg("host", remote_host)));
        send_simple_response(req, HttpErrorForbidden);
        return;
    }

    evhttp_add_header(output_headers, "Access-Control-Allow-Origin", "*");

    auto const* const input_headers = evhttp_request_get_input_headers(req);
    if (auto const cmd = evhttp_request_get_command(req); cmd == EVHTTP_REQ_OPTIONS)
    {
        if (char const* headers = evhttp_find_header(input_headers, "Access-Control-Request-Headers"); headers != nullptr)
        {
            evhttp_add_header(output_headers, "Access-Control-Allow-Headers", headers);
        }

        evhttp_add_header(output_headers, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        send_simple_response(req, HTTP_OK);
        return;
    }

    if (!is_authorized(server, evhttp_find_header(input_headers, "Authorization")))
    {
        tr_logAddWarn(
            fmt::format(
                fmt::runtime(_("Rejected request from {host} (failed authentication)")),
                fmt::arg("host", remote_host)));
        evhttp_add_header(output_headers, "WWW-Authenticate", "Basic realm=\"" MY_REALM "\"");
        if (server->is_anti_brute_force_enabled())
        {
            ++server->login_attempts_;
        }

        send_simple_response(req, HttpErrorUnauthorized);
        return;
    }

    server->login_attempts_ = 0;

    // eg '/transmission/web/' and '/transmission/rpc' and '/transmission/torrents/'
    auto const& base_path = server->url();
    auto const web_base_path = tr_urlbuf{ base_path, TrHttpServerWebRelativePath };
    auto const rpc_base_path = tr_urlbuf{ base_path, TrHttpServerRpcRelativePath };
    auto const torrents_base_path = tr_urlbuf{ base_path, TrHttpServerTorrentsRelativePath };
    auto const deprecated_web_path = tr_urlbuf{ base_path, "web" /*no trailing slash*/ };

    char const* const uri = evhttp_request_get_uri(req);

    if (!tr_strv_starts_with(uri, base_path) || uri == deprecated_web_path)
    {
        evhttp_add_header(output_headers, "Location", web_base_path.c_str());
        send_simple_response(req, HTTP_MOVEPERM, nullptr);
    }
    else if (tr_strv_starts_with(uri, web_base_path))
    {
        handle_web_client(req, server);
    }
    else if (!isHostnameAllowed(server, req))
    {
        static auto constexpr Body =
            "<p>Transmission received your request, but the hostname was unrecognized.</p>"
            "<p>To fix this, choose one of the following options:"
            "<ul>"
            "<li>Enable password authentication, then any hostname is allowed.</li>"
            "<li>Add the hostname you want to use to the whitelist in settings.</li>"
            "</ul></p>"
            "<p>If you're editing settings.json, see the 'rpc_host_whitelist' and 'rpc_host_whitelist_enabled' entries.</p>"
            "<p>This requirement has been added to help prevent "
            "<a href=\"https://en.wikipedia.org/wiki/DNS_rebinding\">DNS Rebinding</a> "
            "attacks.</p>";
        tr_logAddWarn(
            fmt::format(fmt::runtime(_("Rejected request from {host} (Host not whitelisted)")), fmt::arg("host", remote_host)));
        send_simple_response(req, 421, Body);
    }
    else if (server->settings_.is_torrent_serving_enabled && tr_strv_starts_with(uri, torrents_base_path))
    {
        auto subpath = std::string_view{ uri };
        subpath = subpath.substr(std::size(torrents_base_path));
        handle_torrent_content(req, server, subpath);
    }
    else if (uri != rpc_base_path)
    {
        tr_logAddWarn(
            fmt::format(
                fmt::runtime(_("Unknown URI from {host}: '{uri}'")),
                fmt::arg("host", remote_host),
                fmt::arg("uri", uri)));
        send_simple_response(req, HTTP_NOTFOUND, uri);
    }
#ifdef REQUIRE_SESSION_ID
    else if (!test_session_id(server, req))
    {
        auto const session_id = std::string{ server->session->sessionId() };
        evhttp_add_header(output_headers, std::data(TrRpcSessionIdHeader), session_id.c_str());

        evhttp_add_header(output_headers, std::data(TrRpcVersionHeader), std::data(TrRpcVersionSemver));

        auto const expose_val = fmt::format("{:s}, {:s}", TrRpcSessionIdHeader, TrRpcVersionHeader);
        evhttp_add_header(output_headers, "Access-Control-Expose-Headers", expose_val.c_str());

        auto const body = fmt::format(
            "<p>Your request had an invalid session_id header.</p>"
            "<p>To fix this, follow these steps:"
            "<ol><li> When reading a response, get its {0:s} header and remember it"
            "<li> Add the updated header to your outgoing requests"
            "<li> When you get this 409 error message, resend your request with the updated header"
            "</ol></p>"
            "<p>This requirement has been added to help prevent "
            "<a href=\"https://en.wikipedia.org/wiki/Cross-site_request_forgery\">CSRF</a> "
            "attacks.</p>"
            "<p><code>{0:s}: {1:s}</code></p>",
            TrRpcSessionIdHeader,
            session_id);
        send_simple_response(req, 409, body.c_str());
    }
#endif
    else
    {
        handle_rpc(req, server);
    }
}

auto constexpr ServerStartRetryCount = 10;
auto constexpr ServerStartRetryDelayIncrement = 5s;
auto constexpr ServerStartRetryMaxDelay = 60s;

bool bindUnixSocket(
    [[maybe_unused]] struct event_base* base,
    [[maybe_unused]] struct evhttp* httpd,
    [[maybe_unused]] char const* path,
    [[maybe_unused]] tr_mode_t socket_mode)
{
#ifdef _WIN32
    tr_logAddError(
        fmt::format(
            _("Unix sockets are unsupported on Windows. Please change '{key}' in your settings."),
            fmt::arg("key", tr_quark_get_string_view(TR_KEY_rpc_bind_address))));
    return false;
#else
    auto addr = sockaddr_un{};
    addr.sun_family = AF_UNIX;
    *fmt::format_to_n(addr.sun_path, sizeof(addr.sun_path) - 1, "{:s}", path + std::size(TrUnixSocketPrefix)).out = '\0';

    unlink(addr.sun_path);

    struct evconnlistener* lev = evconnlistener_new_bind(
        base,
        nullptr,
        nullptr,
        LEV_OPT_CLOSE_ON_FREE,
        -1,
        reinterpret_cast<sockaddr const*>(&addr),
        sizeof(addr));

    if (lev == nullptr)
    {
        return false;
    }

    if (chmod(addr.sun_path, socket_mode) != 0)
    {
        tr_logAddWarn(
            fmt::format(
                fmt::runtime(_("Couldn't set RPC socket mode to {mode:#o}, defaulting to 0755")),
                fmt::arg("mode", socket_mode)));
    }

    return evhttp_bind_listener(httpd, lev) != nullptr;
#endif
}

void start_server(tr_rpc_server* server);

auto rpc_server_start_retry(tr_rpc_server* server)
{
    if (!server->start_retry_timer)
    {
        server->start_retry_timer = server->session->timerMaker().create([server]() { start_server(server); });
    }

    ++server->start_retry_counter;
    auto const interval = std::min(ServerStartRetryDelayIncrement * server->start_retry_counter, ServerStartRetryMaxDelay);
    server->start_retry_timer->start_single_shot(std::chrono::duration_cast<std::chrono::milliseconds>(interval));
    return interval;
}

void rpc_server_start_retry_cancel(tr_rpc_server* server)
{
    server->start_retry_timer.reset();
    server->start_retry_counter = 0;
}

int tr_evhttp_bind_socket(struct evhttp* httpd, char const* address, ev_uint16_t port)
{
#ifdef _WIN32
    struct addrinfo* result = nullptr;
    struct addrinfo hints = {};
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(address, std::to_string(port).c_str(), &hints, &result) != 0)
    {
        return evhttp_bind_socket(httpd, address, port);
    }

    int const fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        return evhttp_bind_socket(httpd, address, port);
    }
    evutil_make_socket_nonblocking(fd);
    evutil_make_listen_socket_reuseable(fd);

    // Making dual stack
    if (result->ai_family == AF_INET6)
    {
        int off = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&off), sizeof(off));
    }
    // Set keep alive
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char*>(&on), sizeof(on));
    if (bind(fd, result->ai_addr, result->ai_addrlen) != 0 || listen(fd, 128) == -1)
    {
        closesocket(fd);
        freeaddrinfo(result);
        return evhttp_bind_socket(httpd, address, port);
    }
    if (evhttp_accept_socket(httpd, fd) == 0)
    {
        freeaddrinfo(result);
        return 0;
    }
    // Fallback
    closesocket(fd);
    freeaddrinfo(result);
#endif
    return evhttp_bind_socket(httpd, address, port);
}

void start_server(tr_rpc_server* server)
{
    if (server->httpd)
    {
        return;
    }

    auto* const base = server->session->event_base();
    auto* const httpd = evhttp_new(base);

    evhttp_set_allowed_methods(httpd, EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_OPTIONS);

    auto const address = server->get_bind_address();
    auto const port = server->port();

    bool const success = server->bind_address_->is_unix_addr() ?
        bindUnixSocket(base, httpd, address.c_str(), server->settings().socket_mode) :
        (tr_evhttp_bind_socket(httpd, address.c_str(), port.host()) != -1);

    auto const addr_port_str = server->bind_address_->to_string(port);

    if (!success)
    {
        evhttp_free(httpd);

        if (server->start_retry_counter < ServerStartRetryCount)
        {
            auto const retry_delay = rpc_server_start_retry(server);
            auto const seconds = std::chrono::duration_cast<std::chrono::seconds>(retry_delay).count();
            tr_logAddDebug(fmt::format("Couldn't bind to {}, retrying in {} seconds", addr_port_str, seconds));
            return;
        }

        tr_logAddError(
            fmt::format(
                fmt::runtime(tr_ngettext(
                    "Couldn't bind to {address} after {count} attempt, giving up",
                    "Couldn't bind to {address} after {count} attempts, giving up",
                    ServerStartRetryCount)),
                fmt::arg("address", addr_port_str),
                fmt::arg("count", ServerStartRetryCount)));
    }
    else
    {
        evhttp_set_gencb(httpd, handle_request, server);
        server->httpd.reset(httpd);

        tr_logAddInfo(
            fmt::format(
                fmt::runtime(_("Listening for RPC and Web requests on '{address}'")),
                fmt::arg("address", addr_port_str)));
    }

    rpc_server_start_retry_cancel(server);
}

void stop_server(tr_rpc_server* server)
{
    auto const lock = server->session->unique_lock();

    rpc_server_start_retry_cancel(server);

    auto& httpd = server->httpd;
    if (!httpd)
    {
        return;
    }

    auto const address = server->get_bind_address();

    httpd.reset();

    if (server->bind_address_->is_unix_addr())
    {
        unlink(address.c_str() + std::size(TrUnixSocketPrefix));
    }

    tr_logAddInfo(
        fmt::format(
            fmt::runtime(_("Stopped listening for RPC and Web requests on '{address}'")),
            fmt::arg("address", server->bind_address_->to_string(server->port()))));
}

void restart_server(tr_rpc_server* const server)
{
    if (server->is_enabled())
    {
        stop_server(server);
        start_server(server);
    }
}

auto parse_whitelist(std::string_view whitelist)
{
    auto list = std::vector<std::string>{};

    auto item = std::string_view{};
    while (tr_strv_sep(&whitelist, &item, ",;"sv))
    {
        item = tr_strv_strip(item);
        if (!std::empty(item))
        {
            list.emplace_back(item);
            tr_logAddInfo(fmt::format(fmt::runtime(_("Added '{entry}' to host whitelist")), fmt::arg("entry", item)));
        }
    }

    return list;
}

} // namespace

void tr_rpc_server::set_enabled(bool is_enabled)
{
    settings_.is_enabled = is_enabled;

    session->run_in_session_thread(
        [this]()
        {
            if (!settings_.is_enabled)
            {
                stop_server(this);
            }
            else
            {
                start_server(this);
            }
        });
}

void tr_rpc_server::set_port(tr_port port) noexcept
{
    if (settings_.port == port)
    {
        return;
    }

    settings_.port = port;

    if (is_enabled())
    {
        session->run_in_session_thread(&restart_server, this);
    }
}

void tr_rpc_server::set_url(std::string_view url)
{
    settings_.url = url;
    tr_logAddDebug(fmt::format("setting our URL to '{:s}'", url));
}

void tr_rpc_server::set_whitelist(std::string_view whitelist)
{
    settings_.whitelist_str = whitelist;
    whitelist_ = parse_whitelist(whitelist);
}

// --- PASSWORD

void tr_rpc_server::set_username(std::string_view username)
{
    settings_.username = username;
    tr_logAddDebug(fmt::format("setting our username to '{:s}'", username));
}

void tr_rpc_server::set_password(std::string_view password) noexcept
{
    auto const is_salted = tr_ssha1_test(password);
    settings_.salted_password = is_salted ? password : tr_ssha1(password);
    tr_logAddDebug(fmt::format("setting our salted password to '{:s}'", settings_.salted_password));
}

void tr_rpc_server::set_password_enabled(bool enabled)
{
    settings_.authentication_required = enabled;
    tr_logAddDebug(fmt::format("setting password-enabled to '{}'", enabled));
}

std::string tr_rpc_server::get_bind_address() const
{
    return bind_address_->to_string();
}

void tr_rpc_server::set_anti_brute_force_enabled(bool enabled) noexcept
{
    settings_.is_anti_brute_force_enabled = enabled;

    if (!enabled)
    {
        login_attempts_ = 0;
    }
}

// --- LIFECYCLE

tr_rpc_server::tr_rpc_server(tr_session* session_in, Settings&& settings)
    : compressor{ libdeflate_alloc_compressor(DeflateLevel), libdeflate_free_compressor }
    , web_client_dir_{ tr_getWebClientDir(session_in) }
    , bind_address_{ std::make_unique<class tr_rpc_address>() }
    , session{ session_in }
{
    load(std::move(settings));
}

void tr_rpc_server::load(Settings&& settings)
{
    settings_ = std::move(settings);

    if (std::string& path = settings_.url; !tr_strv_ends_with(path, '/'))
    {
        path = fmt::format("{:s}/", path);
    }

    host_whitelist_ = parse_whitelist(settings_.host_whitelist_str);
    set_password_enabled(settings_.authentication_required);
    set_whitelist(settings_.whitelist_str);
    set_username(settings_.username);
    set_password(settings_.salted_password);

    if (!bind_address_->from_string(settings_.bind_address_str))
    {
        // NOTE: bind_address_ is default initialized to INADDR_ANY
        tr_logAddWarn(
            fmt::format(
                fmt::runtime(_(
                    "The '{key}' setting is '{value}' but must be an IPv4 or IPv6 address or a Unix socket path. Using default value '0.0.0.0'")),
                fmt::arg("key", tr_quark_get_string_view(TR_KEY_rpc_bind_address)),
                fmt::arg("value", settings_.bind_address_str)));
    }

    if (bind_address_->is_unix_addr())
    {
        set_whitelist_enabled(false);
        settings_.is_host_whitelist_enabled = false;
    }
    if (this->is_enabled())
    {
        auto const& base_path = url();
        auto const rpc_uri = bind_address_->to_string(port()) + base_path;
        tr_logAddInfo(fmt::format(fmt::runtime(_("Serving RPC and Web requests on {address}")), fmt::arg("address", rpc_uri)));
        session->run_in_session_thread(start_server, this);

        if (this->is_whitelist_enabled())
        {
            tr_logAddInfo(_("Whitelist enabled"));
        }

        if (this->is_password_enabled())
        {
            tr_logAddInfo(_("Password required"));
        }
    }

    if (!std::empty(web_client_dir_))
    {
        tr_logAddInfo(
            fmt::format(fmt::runtime(_("Serving RPC and Web requests from '{path}'")), fmt::arg("path", web_client_dir_)));
    }
}

tr_rpc_server::~tr_rpc_server()
{
    stop_server(this);
}
