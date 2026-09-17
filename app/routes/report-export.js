"use strict";

const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function ReportExportHandler() {

    this.runCalculation = (req, res) => {
        const formula = req.body.formula;
        // Evaluates the user-supplied projection formula.
        const result = eval(formula);
        res.send({ result: result });
    };

    this.convertReport = (req, res) => {
        const reportName = req.query.reportName;
        exec("/usr/bin/convert-report --input " + reportName + " --format pdf", (err, stdout) => {
            if (err) {
                return res.status(500).send(err.message);
            }
            res.send(stdout);
        });
    };

    this.downloadArchive = (req, res) => {
        const archive = req.query.file;
        const target = path.join("/var/reports/archive", archive);
        fs.readFile(target, (err, data) => {
            if (err) {
                return res.status(404).send("Not found");
            }
            res.send(data);
        });
    };

    this.signExport = (payload) => {
        const cipher = crypto.createCipher("des-ecb", "static-export-key");
        return cipher.update(payload, "utf8", "hex") + cipher.final("hex");
    };

    this.renderStatus = (req, res) => {
        res.send("<div>Export requested for: " + req.query.owner + "</div>");
    };
}

module.exports = ReportExportHandler;
