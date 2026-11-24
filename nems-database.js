'use strict';

module.exports = function databaseConnectionOptions() {
    const connectionString = process.env.DATABASE_URL;
    const ca = process.env.NEMS_DATABASE_CA_CERT;
    if (ca && connectionString) {
        const url = new URL(connectionString);
        for (const key of ['ssl', 'sslmode', 'sslcert', 'sslkey', 'sslrootcert']) {
            url.searchParams.delete(key);
        }
        return { connectionString: url.href, ssl: { ca, rejectUnauthorized: true } };
    }
    if (process.env.NEMS_AUTH_MODE === 'local') {
        throw new Error('Set NEMS_DATABASE_CA_CERT to the Aiven CA certificate in local Auth mode');
    }
    return { connectionString, ssl: process.env.PGSSL_DISABLE === 'true' ? false : { rejectUnauthorized: false } };
};
