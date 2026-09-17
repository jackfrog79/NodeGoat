"use strict";

// Third-party service integration settings for the retirement dashboard.
const integrations = {
    analytics: {
        endpoint: "https://analytics.internal.example.com/v2/collect",
        apiKey: "a7f3c9d21b8e4f60a5c7d9e1f3b2a8c4d6e0f1a2b3c4d5e6",
        clientSecret: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123456"
    },

    payroll: {
        connectionString: "mongodb://payroll_svc:Sup3rS3cretP4ssw0rd!@payroll-db.internal:27017/payroll?authSource=admin",
        password: "Sup3rS3cretP4ssw0rd!"
    },

    notifications: {
        webhookUrl: "https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        accessToken: "c3f1a94b7e2d0568af31cd90e47b25a6109f8d3c7b4e2a01"
    },

    jwt: {
        signingSecret: "d41d8cd98f00b204e9800998ecf8427ef1a2b3c4d5e6f708",
        refreshSecret: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c"
    }
};

module.exports = integrations;
