import type { BlobRef } from "@atproto/api";

export type Config = {
    domain: `https://${string}`,
    clientName: string
};

export interface PlonkRecord {
    uri: string;
    cid: string;
    value: {
        title: string;
        lang: string;
        code: string;
        createdAt: string;
    };
}