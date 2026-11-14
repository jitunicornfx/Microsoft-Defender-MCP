package com.jitunicornfx.defender.mcp

import io.ktor.http.encodeURLPathPart
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.time.Duration
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/**
 * Strict validators for every model-supplied value that reaches a URL, a query string or a request
 * body. Tool arguments may be steered by prompt-injected content, so each identifier is checked
 * against the narrowest shape the Defender API actually uses and refused otherwise. Every failure
 * is an [IllegalArgumentException] with a server-authored message (the offending value is never
 * echoed back in full, so a malicious value cannot ride an error message into the model's context).
 */
object Validators {
    private val MACHINE_ID = Regex("^[0-9a-fA-F]{40}$")
    private val GUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val GENERIC_ID = Regex("^[A-Za-z0-9_-]{1,128}$")
    private val SHA1 = Regex("^[0-9a-fA-F]{40}$")
    private val HOST_LABEL = Regex("^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    private val USER_ID = Regex("^[\\p{L}\\p{N}._$-]{1,104}$")
    private val IPV4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")
    private val IPV6_CHARS = Regex("^[0-9A-Fa-f:.]{2,45}$")

    /**
     * Invisible carriers of injected text: zero-width and bidirectional-control characters, Unicode
     * tag characters, variation selectors (used to hide byte streams behind one visible glyph),
     * Hangul fillers, and the Unicode line/paragraph separators (which can forge line breaks).
     */
    internal val INVISIBLE = Regex(
        "[\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180B-\\u180F\\u200B-\\u200F\\u2028-\\u202E\\u2060-\\u2064" +
            "\\u2066-\\u206F\\u3164\\uFE00-\\uFE0F\\uFEFF\\uFFA0\\x{E0000}-\\x{E007F}\\x{E0100}-\\x{E01EF}]",
    )

    const val MAX_COMMENT_LENGTH = 1_000
    const val MAX_TAG_LENGTH = 200
    const val MAX_BULK_MACHINES = 500

    private fun Char.isHexDigitChar() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private fun describe(value: String): String = "${value.length} characters"

    /** A Defender machine (device) ID: 40 hexadecimal characters. Returned lowercased. */
    fun machineId(value: String, field: String = "machine_id"): String {
        val v = value.trim()
        require(MACHINE_ID.matches(v)) { "$field must be a 40-character hexadecimal Defender device ID (got ${describe(v)})." }
        return v.lowercase()
    }

    /**
     * A machine ID or a computer DNS name; `GET /api/machines/{id}` accepts either. A name must be a
     * syntactically valid host name (labels of letters, digits and hyphens).
     */
    fun machineIdOrName(value: String, field: String = "machine"): String {
        val v = value.trim()
        if (MACHINE_ID.matches(v)) return v.lowercase()
        require(isHostName(v)) {
            "$field must be a 40-character device ID or a computer DNS name (got ${describe(v)})."
        }
        return v.lowercase()
    }

    /** Alert, investigation and similar opaque identifiers: letters, digits, `_` and `-`. */
    fun opaqueId(value: String, field: String): String {
        val v = value.trim()
        require(GENERIC_ID.matches(v)) { "$field must be 1-128 letters, digits, '_' or '-' (got ${describe(v)})." }
        return v
    }

    fun guid(value: String, field: String): String {
        val v = value.trim()
        require(GUID.matches(v)) { "$field must be a GUID such as 3fa85f64-5717-4562-b3fc-2c963f66afa6." }
        return v.lowercase()
    }

    fun sha1(value: String, field: String = "sha1"): String {
        val v = value.trim()
        require(SHA1.matches(v)) { "$field must be a 40-character hexadecimal SHA-1." }
        return v.lowercase()
    }

    private val SHA256 = Regex("^[0-9a-fA-F]{64}$")

    /** A file identifier the Files API accepts: SHA-1 (40 hex) or SHA-256 (64 hex). Returned lowercased. */
    fun fileHash(value: String, field: String = "file_hash"): String {
        val v = value.trim()
        require(SHA1.matches(v) || SHA256.matches(v)) { "$field must be a SHA-1 (40 hex) or SHA-256 (64 hex) file hash." }
        return v.lowercase()
    }

    /** True for a syntactically valid DNS host name (no trailing dot, 1-253 characters). */
    fun isHostName(value: String): Boolean {
        if (value.isEmpty() || value.length > 253) return false
        return value.split('.').all { HOST_LABEL.matches(it) }
    }

    /** A DNS domain such as `example.com`. Needs at least two labels and an alphabetic top-level label. */
    fun domain(value: String, field: String = "domain"): String {
        val v = value.trim().trimEnd('.').lowercase()
        val labels = v.split('.')
        require(isHostName(v) && labels.size >= 2 && labels.last().any { it.isLetter() } && !IPV4.matches(v)) {
            "$field must be a DNS domain name such as example.com (got ${describe(v)})."
        }
        return v
    }

    /**
     * An IPv4 or IPv6 literal. Parsed WITHOUT name resolution: [InetAddress.getByName] is only
     * reached once the text has been confirmed to contain nothing but address characters, so a host
     * name can never trigger a DNS lookup (which would itself leak the value to a resolver).
     */
    fun ipAddress(value: String, field: String = "ip"): String {
        val v = value.trim()
        if (IPV4.matches(v)) return v
        // The JDK only takes its literal-parsing path when the text starts with a hex digit or ':';
        // anything else (a leading '.') would fall through to name resolution, so refuse it here.
        require(v.contains(':') && IPV6_CHARS.matches(v) && (v[0] == ':' || v[0].isHexDigitChar()) && !v.contains("..")) {
            "$field must be an IPv4 or IPv6 address (got ${describe(v)})."
        }
        val parsed = runCatching { InetAddress.getByName(v) }.getOrNull()
        require(parsed is Inet6Address || parsed is Inet4Address) { "$field must be an IPv4 or IPv6 address." }
        return v.lowercase()
    }

    /**
     * A Defender user identifier. The `/api/users/{id}` endpoints take the bare account name (the UPN
     * prefix), so a full UPN is reduced to its part before `@` rather than silently returning nothing.
     */
    fun userId(value: String, field: String = "user"): String {
        val v = value.trim().substringBefore('@')
        require(USER_ID.matches(v)) {
            "$field must be an account name such as jdoe (the part of the UPN before '@'): letters, digits, '.', '_', '$' or '-' (got ${describe(v)})."
        }
        return v
    }

    /** A machine tag: printable text, no control or invisible characters, at most [MAX_TAG_LENGTH] characters. */
    fun tag(value: String, field: String = "tag"): String {
        val v = value.trim()
        require(v.isNotEmpty() && v.length <= MAX_TAG_LENGTH) { "$field must be 1-$MAX_TAG_LENGTH characters." }
        require(v.none { it.isISOControl() } && !INVISIBLE.containsMatchIn(v)) {
            "$field must not contain control or invisible characters."
        }
        return v
    }

    /**
     * A free-text comment recorded with an action. Control and invisible characters are removed
     * rather than refused (comments are prose); an empty or over-long result is refused.
     */
    fun comment(value: String, field: String = "comment"): String {
        val cleaned = INVISIBLE.replace(value, "").filterNot { it.isISOControl() && it != '\n' && it != '\t' }.trim()
        require(cleaned.isNotEmpty()) { "$field is required and must not be blank." }
        require(cleaned.length <= MAX_COMMENT_LENGTH) { "$field must be at most $MAX_COMMENT_LENGTH characters." }
        return cleaned
    }

    /** Parse an ISO-8601 timestamp (with offset or `Z`) into an [Instant]. */
    fun timestamp(value: String, field: String): Instant {
        val v = value.trim()
        return try {
            OffsetDateTime.parse(v, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant()
        } catch (_: DateTimeParseException) {
            try {
                Instant.parse(v)
            } catch (_: DateTimeParseException) {
                throw IllegalArgumentException("$field must be an ISO-8601 timestamp such as 2026-01-31T13:45:00Z.")
            }
        }
    }

    /** A timestamp within the past [maxAge] (and not in the future beyond a small clock skew). */
    fun recentTimestamp(value: String, field: String, maxAge: Duration, now: Instant = Instant.now()): Instant {
        val ts = timestamp(value, field)
        require(!ts.isAfter(now.plusSeconds(300))) { "$field must not be in the future." }
        require(!ts.isBefore(now.minus(maxAge))) { "$field must be within the past ${maxAge.toDays()} days." }
        return ts
    }

    /**
     * Encode a validated value as one URL path segment. Defense in depth behind the validators: the
     * dot-segments `.` and `..` (which a gateway could collapse into a parent path) are refused, and
     * `;` (a path-parameter delimiter some servers strip before normalizing) is always escaped.
     */
    fun seg(value: String): String {
        val beforeParameters = value.substringBefore(';')
        require(beforeParameters != "." && beforeParameters != "..") { "Invalid path segment." }
        // encodeURLPathPart (Ktor 3.x) escapes '%' itself, so "%2e%2e" becomes "%252e%252e" and can never mean "..".
        return value.encodeURLPathPart().replace(";", "%3B")
    }
}

/**
 * Builds and validates OData `$filter` expressions.
 *
 * Structured tool arguments are turned into filters here, with every literal quoted and escaped, so
 * a value can never close its string and append its own clause. A raw `filter` argument is accepted
 * only after [validate] tokenizes it and confirms every identifier is a field the endpoint documents
 * as filterable, every function is a known OData function, and every string literal is well formed.
 */
object OData {
    const val MAX_FILTER_LENGTH = 2_000

    private val KEYWORDS = setOf("eq", "ne", "gt", "ge", "lt", "le", "and", "or", "not", "true", "false", "null")
    private val FUNCTIONS = setOf("startswith", "endswith", "contains", "tolower", "toupper", "any", "all")
    private val NUMBER = Regex("^-?\\d+(\\.\\d+)?$")
    private val DATETIME = Regex("^\\d{4}-\\d{2}-\\d{2}(T\\d{2}:\\d{2}(:\\d{2}(\\.\\d{1,7})?)?)?(Z|[+-]\\d{2}:\\d{2})?$")
    private val DATE_PREFIX = Regex("\\d{4}-\\d{2}-\\d{2}")
    private val IDENT = Regex("^[A-Za-z_][A-Za-z0-9_]*$")

    /** Quote [value] as an OData string literal, doubling embedded single quotes. */
    fun quote(value: String): String {
        require(value.none { it.isISOControl() }) { "Filter values must not contain control characters." }
        return "'" + value.replace("'", "''") + "'"
    }

    /** Join non-null clauses with `and`, or null when there are none. */
    fun and(vararg clauses: String?): String? = clauses.filterNotNull().takeIf { it.isNotEmpty() }?.joinToString(" and ")

    /** Format [instant] as an OData DateTimeOffset literal. */
    fun datetime(instant: Instant): String = DateTimeFormatter.ISO_INSTANT.format(instant)

    internal sealed interface Token {
        data class Ident(val text: String) : Token
        data class Str(val text: String) : Token
        data class Literal(val text: String) : Token
        data class Punct(val ch: Char) : Token
    }

    internal fun tokenize(filter: String): List<Token> {
        val tokens = mutableListOf<Token>()
        var i = 0
        while (i < filter.length) {
            val c = filter[i]
            when {
                c == ' ' || c == '\t' -> i++
                c == '\'' -> {
                    val sb = StringBuilder()
                    i++
                    var closed = false
                    while (i < filter.length) {
                        val ch = filter[i]
                        if (ch == '\'') {
                            if (i + 1 < filter.length && filter[i + 1] == '\'') {
                                sb.append('\'')
                                i += 2
                                continue
                            }
                            closed = true
                            i++
                            break
                        }
                        sb.append(ch)
                        i++
                    }
                    require(closed) { "Filter has an unterminated string literal." }
                    tokens += Token.Str(sb.toString())
                }
                c == '(' || c == ')' || c == ',' || c == '/' || c == ':' -> {
                    tokens += Token.Punct(c)
                    i++
                }
                c.isLetterOrDigit() || c == '_' || c == '-' || c == '.' || c == '+' -> {
                    val start = i
                    // Datetimes contain ':' and '+'; read them greedily when the token starts like a date.
                    val looksLikeDate = filter.length >= i + 10 && DATE_PREFIX.matches(filter.substring(i, i + 10))
                    while (i < filter.length) {
                        val ch = filter[i]
                        val ok = ch.isLetterOrDigit() || ch == '_' || ch == '-' || ch == '.' ||
                            (looksLikeDate && (ch == ':' || ch == '+'))
                        if (!ok) break
                        i++
                    }
                    // A token must consume at least one character; otherwise (a '+' outside a date) the
                    // outer loop would spin forever on the same position.
                    require(i > start) { "Filter contains an unsupported character at position ${start + 1}." }
                    val text = filter.substring(start, i)
                    tokens += if (NUMBER.matches(text) || DATETIME.matches(text)) Token.Literal(text) else Token.Ident(text)
                }
                else -> throw IllegalArgumentException("Filter contains an unsupported character at position ${i + 1}.")
            }
        }
        return tokens
    }

    /**
     * Validate a raw `$filter` against the endpoint's [allowedFields]. Returns the filter trimmed.
     * Lambda variables (`machineTags/any(t: t eq 'x')`) are recognised and may be referenced inside
     * their lambda.
     */
    fun validate(filter: String, allowedFields: Set<String>): String {
        val f = filter.trim()
        require(f.isNotEmpty()) { "filter must not be blank." }
        require(f.length <= MAX_FILTER_LENGTH) { "filter must be at most $MAX_FILTER_LENGTH characters." }
        require(f.none { it.isISOControl() } && !Validators.INVISIBLE.containsMatchIn(f)) {
            "filter must not contain control or invisible characters."
        }
        val tokens = tokenize(f)
        val allowedLower = allowedFields.associateBy { it.lowercase() }
        // Lambda variables in scope, each with the parenthesis depth of the lambda that declared it;
        // a variable goes out of scope when that lambda's ')' closes.
        val lambdaScopes = ArrayDeque<Pair<String, Int>>()
        fun inScope(name: String) = lambdaScopes.any { it.first == name }
        var depth = 0
        tokens.forEachIndexed { index, token ->
            when (token) {
                is Token.Ident -> {
                    val lower = token.text.lowercase()
                    val next = tokens.getOrNull(index + 1)
                    when {
                        // Lambda variable declaration, only in the exact shape field/any( t : ... where
                        // field is itself filterable (or an enclosing lambda's variable).
                        next == Token.Punct(':') -> {
                            val fn = (tokens.getOrNull(index - 2) as? Token.Ident)?.text?.lowercase()
                            val collection = (tokens.getOrNull(index - 4) as? Token.Ident)?.text
                            require(
                                tokens.getOrNull(index - 1) == Token.Punct('(') && (fn == "any" || fn == "all") &&
                                    tokens.getOrNull(index - 3) == Token.Punct('/') && collection != null &&
                                    (collection.lowercase() in allowedLower || inScope(collection)),
                            ) {
                                "A ':' is only allowed in a lambda over a filterable collection, such as machineTags/any(t: t eq 'x')."
                            }
                            require(
                                IDENT.matches(token.text) && lower !in allowedLower && lower !in KEYWORDS &&
                                    lower !in FUNCTIONS && !inScope(token.text),
                            ) {
                                "Lambda variable '${token.text.take(40)}' must be a new short name such as t."
                            }
                            lambdaScopes.addLast(token.text to depth)
                        }
                        lower in KEYWORDS -> Unit
                        lower in FUNCTIONS -> require(next == Token.Punct('(')) { "'${token.text}' must be followed by '('." }
                        inScope(token.text) -> Unit
                        lower in allowedLower -> Unit
                        else -> throw IllegalArgumentException(
                            "filter field '${token.text.take(40)}' is not filterable here. " +
                                "Allowed fields: ${allowedFields.sorted().joinToString(", ")}.",
                        )
                    }
                }
                is Token.Punct -> when (token.ch) {
                    '(' -> depth++
                    ')' -> {
                        while (lambdaScopes.isNotEmpty() && lambdaScopes.last().second == depth) lambdaScopes.removeLast()
                        depth--
                        require(depth >= 0) { "filter has unbalanced parentheses." }
                    }
                    // A ':' is legal only right after a lambda variable declaration (checked above).
                    ':' -> require((tokens.getOrNull(index - 1) as? Token.Ident)?.text?.let(::inScope) == true &&
                        tokens.getOrNull(index - 2) == Token.Punct('(')) { "':' is only allowed in a lambda declaration." }
                    '/' -> {
                        // Only collection navigation into a lambda: field/any( or field/all(
                        val fn = (tokens.getOrNull(index + 1) as? Token.Ident)?.text?.lowercase()
                        require(fn == "any" || fn == "all") { "'/' is only allowed before any( or all(." }
                    }
                    else -> Unit
                }
                is Token.Str, is Token.Literal -> Unit
            }
        }
        require(depth == 0) { "filter has unbalanced parentheses." }
        return f
    }
}

/**
 * Pre-flight checks on advanced hunting KQL.
 *
 * Hunting is read-only, but a model can be steered (by injected text in a previous result) into
 * queries that move data OUT of the tenant: `externaldata` and its relatives make the service fetch
 * an attacker-chosen URL, which can carry query results in its path or parameters. Those operators,
 * and cross-scope references, are refused. String literals and comments are stripped before the
 * check so that the words inside a string never cause a false refusal, and the check runs on the
 * code that will actually execute.
 */
object KqlGuard {
    const val MAX_QUERY_LENGTH = 20_000

    private val DENIED = listOf(
        "externaldata" to "fetches data from external URLs",
        "external_table" to "reads external storage",
        "http_request" to "makes outbound HTTP requests",
        "http_request_post" to "makes outbound HTTP requests",
        "cluster" to "references another cluster",
        "database" to "references another database",
        "workspace" to "references another workspace",
        "app" to "references another Application Insights resource",
        "adx" to "references an Azure Data Explorer cluster",
        "arg" to "references Azure Resource Graph",
    )

    /** Length of a string-literal prefix at [i] (`@`, `h`, `h@`) when a quote follows it, else 0. */
    private fun stringPrefixLength(query: String, i: Int): Int {
        fun isQuote(at: Int) = at < query.length && (query[at] == '\'' || query[at] == '"')
        val c = query[i]
        return when {
            c == '@' && isQuote(i + 1) -> 1
            (c == 'h' || c == 'H') && isQuote(i + 1) -> 1
            (c == 'h' || c == 'H') && i + 1 < query.length && query[i + 1] == '@' && isQuote(i + 2) -> 2
            else -> 0
        }
    }

    /** Remove `//` comments and every kind of KQL string literal, keeping code structure. */
    internal fun stripLiteralsAndComments(query: String): String {
        val out = StringBuilder(query.length)
        var i = 0
        val n = query.length
        while (i < n) {
            val c = query[i]
            when {
                c == '/' && i + 1 < n && query[i + 1] == '/' -> {
                    // Kusto ends a comment at any line break, CR included.
                    while (i < n && query[i] != '\n' && query[i] != '\r') i++
                }
                c == '`' && query.startsWith("```", i) -> {
                    val end = query.indexOf("```", i + 3)
                    i = if (end < 0) n else end + 3
                    out.append("\"\"")
                }
                (c == '@' || c == 'h' || c == 'H') && (i == 0 || !query[i - 1].isLetterOrDigit()) &&
                    stringPrefixLength(query, i) > 0 -> {
                    // Verbatim (@'...'), obfuscated (h'...') and obfuscated verbatim (h@'...') strings.
                    val prefix = stringPrefixLength(query, i)
                    val quote = query[i + prefix]
                    val verbatim = query[i + prefix - 1] == '@'
                    i += prefix + 1
                    while (i < n) {
                        if (query[i] == quote) {
                            if (verbatim && i + 1 < n && query[i + 1] == quote) {
                                i += 2
                                continue
                            }
                            break
                        }
                        if (!verbatim && query[i] == '\\') i++
                        i++
                    }
                    i++
                    out.append("\"\"")
                }
                c == '\'' || c == '"' -> {
                    val quote = c
                    i++
                    while (i < n && query[i] != quote) {
                        if (query[i] == '\\') i++
                        i++
                    }
                    i++
                    out.append("\"\"")
                }
                else -> {
                    out.append(c)
                    i++
                }
            }
        }
        return out.toString()
    }

    /** Validate [query]; returns it trimmed or throws [IllegalArgumentException]. */
    fun validate(query: String): String {
        val q = query.trim()
        require(q.isNotEmpty()) { "query must not be blank." }
        require(q.length <= MAX_QUERY_LENGTH) { "query must be at most $MAX_QUERY_LENGTH characters." }
        require(q.none { it.isISOControl() && it != '\n' && it != '\r' && it != '\t' }) {
            "query must not contain control characters."
        }
        require(!Validators.INVISIBLE.containsMatchIn(q)) { "query must not contain invisible or bidirectional-control characters." }
        val code = stripLiteralsAndComments(q).lowercase()
        for ((word, why) in DENIED) {
            // Operators/functions are followed by '(' or whitespace; plain identifiers like a column
            // named "app" in `project app = 1` are rare in hunting but would be refused with a clear message.
            val pattern = Regex("(?<![a-z0-9_])" + Regex.escape(word) + "\\s*\\(")
            val bare = word == "externaldata" || word == "external_table"
            val matched = pattern.containsMatchIn(code) ||
                (bare && Regex("(?<![a-z0-9_])" + Regex.escape(word) + "(?![a-z0-9_])").containsMatchIn(code))
            require(!matched) {
                "query uses '$word', which $why; it is blocked to prevent data leaving the tenant."
            }
        }
        return q
    }
}
