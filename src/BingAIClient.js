import './fetch-polyfill.js';
import crypto from 'crypto';
import WebSocket from 'ws';
import Keyv from 'keyv';
import { Agent, ProxyAgent } from 'undici';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { BingImageCreator } from '@timefox/bic-sydney';

/**
 * https://stackoverflow.com/a/58326357
 * @param {number} size
 */
const genRanHex = size => [...Array(size)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');

export default class BingAIClient {
    constructor(options) {
        if (options.keyv) {
            if (!options.keyv.namespace) {
                console.warn('The given Keyv object has no namespace. This is a bad idea if you share a database.');
            }
            this.conversationsCache = options.keyv;
        } else {
            const cacheOptions = options.cache || {};
            cacheOptions.namespace = cacheOptions.namespace || 'bing';
            this.conversationsCache = new Keyv(cacheOptions);
        }

        this.setOptions(options);
    }

    setOptions(options) {
        // don't allow overriding cache options for consistency with other clients
        delete options.cache;
        if (this.options && !this.options.replaceOptions) {
            this.options = {
                ...this.options,
                ...options,
            };
        } else {
            this.options = {
                ...options,
                host: options.host || 'https://www.bing.com',
                xForwardedFor: this.constructor.getValidIPv4(options.xForwardedFor),
                features: {
                    genImage: options?.features?.genImage || false,
                },
            };
        }
        this.debug = this.options.debug;
        if (this.options.features.genImage) {
            this.bic = new BingImageCreator(this.options);
        }
    }

    static getValidIPv4(ip) {
        const match = !ip
            || ip.match(/^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$/);
        if (match) {
            if (match[5]) {
                const mask = parseInt(match[5], 10);
                let [a, b, c, d] = ip.split('.').map(x => parseInt(x, 10));
                // eslint-disable-next-line no-bitwise
                const max = (1 << (32 - mask)) - 1;
                const rand = Math.floor(Math.random() * max);
                d += rand;
                c += Math.floor(d / 256);
                d %= 256;
                b += Math.floor(c / 256);
                c %= 256;
                a += Math.floor(b / 256);
                b %= 256;
                return `${a}.${b}.${c}.${d}`;
            }
            return ip;
        }
        return undefined;
    }

    async createNewConversation() {
        this.headers = {
            accept: 'application/json',
            'accept-encoding': 'gzip, deflate, br, zsdch, zstd',
            'accept-language': 'pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'content-type': 'application/json',
            'sec-ch-ua': '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            'sec-ch-ua-arch': '"x86"',
            'sec-ch-ua-bitness': '"64"',
            'sec-ch-ua-full-version': '"130.0.2849.13"',
            'sec-ch-ua-full-version-list': '"Chromium";v="130.0.6723.19", "Microsoft Edge";v="130.0.2849.13", "Not?A_Brand";v="99.0.0.0"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-model': '""',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"15.0.0"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-ms-gec': genRanHex(64).toUpperCase(),
            'sec-ms-gec-version': '1-130.0.2849.13',
            'x-ms-client-request-id': crypto.randomUUID(),
            'x-ms-useragent': 'azsdk-js-api-client-factory/1.0.0-beta.1 core-rest-pipeline/1.16.0 OS/Windows',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
            cookie: this.options.cookies || (this.options.userToken ? `_U=${this.options.userToken}` : undefined),
            'ect': '4g',
            Referer: 'https://www.bing.com/chat?form=NTPCHB',
            'Referrer-Policy': 'origin-when-cross-origin',
            // Workaround for request being blocked due to geolocation
            'x-forwarded-for': '13.104.0.0/14', // 1.1.1.1 seems to no longer work.
            ...(this.options.xForwardedFor ? { 'x-forwarded-for': this.options.xForwardedFor } : {}),
        };
        // filter undefined values
        this.headers = Object.fromEntries(Object.entries(this.headers).filter(([, value]) => value !== undefined));

        const fetchOptions = {
            headers: this.headers,
        };
        if (this.options.proxy) {
            fetchOptions.dispatcher = new ProxyAgent(this.options.proxy);
        } else {
            fetchOptions.dispatcher = new Agent({ connect: { timeout: 20_000 } });
        }
        
        console.log('> Enviando requisição para criar conversa...'); // Log antes da requisição
        const response = await fetch(`${this.options.host}/turing/conversation/create?bundleVersion=1.1816.0`, fetchOptions);
        console.log('> Resposta recebida para criar conversa...'); // Log após a requisição
        
        const body = await response.text();
        console.log('> Corpo da resposta (texto):', body); // Log do corpo da resposta em formato texto
        
        try {
            const res = JSON.parse(body);
            console.log('> Corpo da resposta (JSON):', res); // Log do corpo da resposta em formato JSON
            res.encryptedConversationSignature = response.headers.get('x-sydney-encryptedconversationsignature') ?? null;
            return res;
        } catch (err) {
            console.error('> Erro ao analisar o corpo da resposta:', err); // Log do erro
            throw new Error(`/turing/conversation/create: failed to parse response body.\n${body}`);
        }
    }

    async createWebSocketConnection(encryptedConversationSignature) {
        return new Promise((resolve, reject) => {
            let agent;
            if (this.options.proxy) {
                agent = new HttpsProxyAgent(this.options.proxy);
            }

            const ws = new WebSocket(`wss://sydney.bing.com/sydney/ChatHub?sec_access_token=${encodeURIComponent(encryptedConversationSignature)}`, { agent, headers: this.headers });

            ws.on('error', err => {
                console.error('> Erro na conexão WebSocket:', err); // Log do erro
                reject(err);
            });

            ws.on('open', () => {
                if (this.debug) {
                    console.debug('> Handshake WebSocket iniciado...');
                }
                ws.send('{"protocol":"json","version":1} ');
            });

            ws.on('close', () => {
                if (this.debug) {
                    console.debug('> Conexão WebSocket fechada.');
                }
            });

            ws.on('message', (data) => {
                console.log('> Mensagem WebSocket recebida (bruta):', data.toString()); // Log da mensagem bruta

                const objects = data.toString().split(' ');
                const messages = objects.map((object) => {
                    try {
                        return JSON.parse(object);
                    } catch (error) {
                        console.error('> Erro ao analisar mensagem WebSocket:', error); // Log do erro
                        return object;
                    }
                }).filter(message => message);

                console.log('> Mensagem WebSocket processada:', messages); // Log da mensagem processada
                
                if (messages.length === 0) {
                    return;
                }
                if (typeof messages[0] === 'object' && Object.keys(messages[0]).length === 0) {
                    if (this.debug) {
                        console.debug('> Handshake WebSocket estabelecido.');
                    }
                    // ping
                    ws.bingPingInterval = setInterval(() => {
                        ws.send('{"type":6} ');
                        // same message is sent back on/after 2nd time as a pong
                    }, 15 * 1000);
                    resolve(ws);
                    return;
                }
                if (this.debug) {
                    console.debug(JSON.stringify(messages));
                    console.debug();
                }
            });
        });
    }

    static cleanupWebSocketConnection(ws) {
        clearInterval(ws.bingPingInterval);
        ws.close();
        ws.removeAllListeners();
    }

    async sendMessage(
        message,
        opts = {},
    ) {
        if (opts.clientOptions && typeof opts.clientOptions === 'object') {
            this.setOptions(opts.clientOptions);
        }

        let {
            jailbreakConversationId = false, 
            conversationId,
            encryptedConversationSignature,
            clientId,
            onProgress,
        } = opts;

        const {
            toneStyle = 'creative', 
            invocationId = 0,
            systemMessage,
            context,
            parentMessageId = jailbreakConversationId === true ? crypto.randomUUID() : null,
            abortController = new AbortController(),
        } = opts;

        if (typeof onProgress !== 'function') {
            onProgress = () => { };
        }

        if (jailbreakConversationId || !encryptedConversationSignature || !conversationId || !clientId) {
            const createNewConversationResponse = await this.createNewConversation();
            if (this.debug) {
                console.debug(createNewConversationResponse);
            }
            if (
                !createNewConversationResponse.encryptedConversationSignature
                || !createNewConversationResponse.conversationId
                || !createNewConversationResponse.clientId
            ) {
                const resultValue = createNewConversationResponse.result?.value;
                if (resultValue) {
                    const e = new Error(createNewConversationResponse.result.message); 
                    e.name = resultValue;
                    throw e;
                }
                throw new Error(`Unexpected response:\n${JSON.stringify(createNewConversationResponse, null, 2)}`);
            }
            ({
                encryptedConversationSignature,
                conversationId,
                clientId,
            } = createNewConversationResponse);
        }

        const stopToken = '\n\n[user](#message)';

        if (jailbreakConversationId === true) {
            jailbreakConversationId = crypto.randomUUID();
        }

        const conversationKey = jailbreakConversationId;

        let previousMessagesFormatted;
        let conversation;
        
        conversation = (await this.conversationsCache.get(conversationKey)) || {
            messages: [],
            createdAt: Date.now(),
        };

        // Mensagem do sistema para o modo normal (sem Jailbreak)
        const systemMessage2 = 'Você é um assistente de IA útil e informativo.'; // Adapte esta mensagem conforme necessário

        const previousCachedMessages = this.constructor.getMessagesForConversation(conversation.messages, parentMessageId)
            .map(conversationMessage => ({
                text: conversationMessage.message,
                author: conversationMessage.role === 'User' ? 'user' : 'bot',
            }));

        const previousMessages = invocationId === 0
            ? [
                {
                    text: jailbreakConversationId ? systemMessage : systemMessage2, // Escolha da mensagem do sistema
                    author: 'system',
                },
                ...previousCachedMessages,
                {
                    text: message,
                    author: 'user',
                },
            ]
            : undefined;

        previousMessagesFormatted = previousMessages?.map((previousMessage) => {
            switch (previousMessage.author) {
                case 'user':
                    return `[user](#message)\n${previousMessage.text}`;
                case 'bot':
                    return `[assistant](#message)\n${previousMessage.text}`;
                case 'system':
                    return `[system](#additional_instructions)\n${previousMessage.text}`;
                default:
                    throw new Error(`Unknown message author: ${previousMessage.author}`);
            }
        }).join('\n\n');

        if (context) {
            previousMessagesFormatted = `${context}\n\n${previousMessagesFormatted}`;
        }
        

        const userMessage = {
            id: crypto.randomUUID(),
            parentMessageId,
            role: 'User',
            message,
        };

        
        conversation.messages.push(userMessage);
        

        const ws = await this.createWebSocketConnection(encryptedConversationSignature);

        ws.on('error', (error) => {
            console.error('> Erro na conexão WebSocket:', error); // Log do erro
            abortController.abort();
        });

        let toneOption;
        if (toneStyle === 'creative') {
            toneOption = 'h3imaginative';
        } else if (toneStyle === 'precise') {
            toneOption = 'h3precise';
        } else if (toneStyle === 'fast') {
            toneOption = 'galileo';
        } else {
            toneOption = 'harmonyv3';
        }

        const obj = {
            arguments: [
                {
                    source: 'cib',
                    optionsSets: [
                        'nlu_direct_response_filter',
                        'deepleo',
                        'responsible_ai_policy_235',
                        'disable_emoji_spoken_text',
                        'enablemm',
                        toneOption,
                        'dtappid',
                        'cricinfo',
                        'cricinfov2',
                        'dv3sugg',
                        'nojbfedge',
                        ...((toneStyle === 'creative' && this.options.features.genImage) ? ['gencontentv3'] : []),
                    ],
                    sliceIds: [
                        '222dtappid',
                        '225cricinfo',
                        '224locals0',
                    ],
                    traceId: genRanHex(32),
                    isStartOfSession: invocationId === 0,
                    message: {
                        author: 'user',
                        text:  'Continue the conversation in context. Assistant:', 
                        messageType: 'SearchQuery', 
                    },
                    encryptedConversationSignature,
                    participant: {
                        id: clientId,
                    },
                    conversationId,
                    previousMessages: [],
                },
            ],
            invocationId: invocationId.toString(),
            target: 'chat',
            type: 4,
        };

        
        if (previousMessagesFormatted) {
            obj.arguments[0].previousMessages.push({
                author: 'user',
                description: previousMessagesFormatted,
                contextType: 'WebPage',
                messageType: 'Context',
                messageId: 'discover-web--page-ping-mriduna-----',
            });
        }
        

        
        if (!jailbreakConversationId && context) {
            obj.arguments[0].previousMessages.push({
                author: 'user',
                description: context,
                contextType: 'WebPage',
                messageType: 'Context',
                messageId: 'discover-web--page-ping-mriduna-----',
            });
        }
        

        if (obj.arguments[0].previousMessages.length === 0) {
            delete obj.arguments[0].previousMessages;
        }

        console.log('> Mensagem enviada para o WebSocket:', JSON.stringify(obj)); // Log da mensagem enviada
        
        const messagePromise = new Promise((resolve, reject) => {
            let replySoFar = '';
            let stopTokenFound = false;

            const messageTimeout = setTimeout(() => {
                this.constructor.cleanupWebSocketConnection(ws);
                reject(new Error('Timed out waiting for response. Try enabling debug mode to see more information.'));
            }, 300 * 1000);

            abortController.signal.addEventListener('abort', () => {
                clearTimeout(messageTimeout);
                this.constructor.cleanupWebSocketConnection(ws);
                reject(new Error('Request aborted'));
            });

            let bicIframe;
            ws.on('message', async (data) => {
                console.log('> Mensagem recebida do WebSocket:', data.toString()); // Log da mensagem recebida

                const objects = data.toString().split(' ');
                const events = objects.map((object) => {
                    try {
                        return JSON.parse(object);
                    } catch (error) {
                        console.error('> Erro ao analisar mensagem do WebSocket:', error); // Log do erro
                        return object;
                    }
                }).filter(eventMessage => eventMessage);
                if (events.length === 0) {
                    return;
                }
                const event = events[0];
                console.log('> Evento WebSocket:', event); // Log do evento

                switch (event.type) {
                    case 1: {
                        if (stopTokenFound) {
                            return;
                        }
                        const messages = event?.arguments?.[0]?.messages;
                        if (!messages?.length || messages[0].author !== 'bot') {
                            return;
                        }
                        if (messages[0].contentOrigin === 'Apology') {
                            return;
                        }
                        if (messages[0]?.contentType === 'IMAGE') {
                            bicIframe = this.bic.genImageIframeSsr(
                                messages[0].text,
                                messages[0].messageId,
                                progress => (progress?.contentIframe ? onProgress(progress?.contentIframe) : null),
                            ).catch((error) => {
                                onProgress(error.message);
                                bicIframe.isError = true;
                                return error.message;
                            });
                            return;
                        }
                        const updatedText = messages[0].text;
                        if (!updatedText || updatedText === replySoFar) {
                            return;
                        }
                        const difference = updatedText.substring(replySoFar.length);
                        onProgress(difference);
                        if (updatedText.trim().endsWith(stopToken)) {
                            stopTokenFound = true;
                            replySoFar = updatedText.replace(stopToken, '').trim();
                            return;
                        }
                        replySoFar = updatedText;
                        return;
                    }
                    case 2: {
                        clearTimeout(messageTimeout);
                        this.constructor.cleanupWebSocketConnection(ws);
                        if (event.item?.result?.value === 'InvalidSession') {
                            reject(new Error(`${event.item.result.value}: ${event.item.result.message}`));
                            return;
                        }
                        const messages = event.item?.messages || [];
                        let eventMessage = messages.length ? messages[messages.length - 1] : null;
                        if (event.item?.result?.error) {
                            if (this.debug) {
                                console.debug(event.item.result.value, event.item.result.message);
                                console.debug(event.item.result.error);
                                console.debug(event.item.result.exception);
                            }
                            if (replySoFar && eventMessage) {
                                eventMessage.adaptiveCards[0].body[0].text = replySoFar;
                                eventMessage.text = replySoFar;
                                resolve({
                                    message: eventMessage,
                                    conversationExpiryTime: event?.item?.conversationExpiryTime,
                                });
                                return;
                            }
                            reject(new Error(`${event.item.result.value}: ${event.item.result.message}`));
                            return;
                        }
                        if (!eventMessage) {
                            reject(new Error('No message was generated.'));
                            return;
                        }
                        if (eventMessage?.author !== 'bot') {
                            reject(new Error('Unexpected message author.'));
                            return;
                        }
                        if (
                            jailbreakConversationId
                            && (
                                stopTokenFound
                                || event.item.messages[0].topicChangerText
                                || event.item.messages[0].offense === 'OffenseTrigger'
                                || (event.item.messages.length > 1 && event.item.messages[1].contentOrigin === 'Apology')
                            )
                        ) {
                            if (!replySoFar) {
                                replySoFar = '[Error: The moderation filter triggered. Try again with different wording.]';
                            }
                            eventMessage.adaptiveCards[0].body[0].text = replySoFar;
                            eventMessage.text = replySoFar;
                            delete eventMessage.suggestedResponses;
                        }
                        if (bicIframe) {
                            let i = messages.length - 1;
                            while (eventMessage?.contentType === 'IMAGE' && i > 0) {
                                eventMessage = messages[i -= 1];
                            }
                            const imgIframe = await bicIframe;
                            if (!imgIframe?.isError) {
                                eventMessage.adaptiveCards[0].body[0].text += imgIframe;
                            } else {
                                eventMessage.text += `<br>${imgIframe}`;
                                eventMessage.adaptiveCards[0].body[0].text = eventMessage.text;
                            }
                        }
                        resolve({
                            message: eventMessage,
                            conversationExpiryTime: event?.item?.conversationExpiryTime,
                        });
                        return;
                    }
                    case 7: {
                        clearTimeout(messageTimeout);
                        this.constructor.cleanupWebSocketConnection(ws);
                        reject(new Error(event.error || 'Connection closed with an error.'));
                        return;
                    }
                    default:
                        if (event?.error) {
                            clearTimeout(messageTimeout);
                            this.constructor.cleanupWebSocketConnection(ws);
                            reject(new Error(`Event Type('${event.type}'): ${event.error}`));
                        }
                        return;
                }
            });
        });

        const messageJson = JSON.stringify(obj);
        if (this.debug) {
            console.debug(messageJson);
            console.debug('\n\n\n\n');
        }
        ws.send(`${messageJson} `);

        const {
            message: reply,
            conversationExpiryTime,
        } = await messagePromise;

        const replyMessage = {
            id: crypto.randomUUID(),
            parentMessageId: userMessage.id,
            role: 'Bing',
            message: reply.text,
            details: reply,
        };
        
        conversation.messages.push(replyMessage);
        await this.conversationsCache.set(conversationKey, conversation);
        

        const returnData = {
            conversationId,
            encryptedConversationSignature,
            clientId,
            invocationId: invocationId + 1,
            conversationExpiryTime,
            response: reply.text,
            details: reply,
        };

        
        returnData.jailbreakConversationId = jailbreakConversationId;
        returnData.parentMessageId = replyMessage.parentMessageId;
        returnData.messageId = replyMessage.id;
        

        return returnData;
    }

    /**
     * Iterate through messages, building an array based on the parentMessageId.
     * Each message has an id and a parentMessageId. The parentMessageId is the id of the message that this message is a reply to.
     * @param messages
     * @param parentMessageId
     * @returns {*[]} An array containing the messages in the order they should be displayed, starting with the root message.
     */
    static getMessagesForConversation(messages, parentMessageId) {
        const orderedMessages = [];
        let currentMessageId = parentMessageId;
        while (currentMessageId) {
            // eslint-disable-next-line no-loop-func
            const message = messages.find(m => m.id === currentMessageId);
            if (!message) {
                break;
            }
            orderedMessages.unshift(message);
            currentMessageId = message.parentMessageId;
        }

        return orderedMessages;
    }
}
