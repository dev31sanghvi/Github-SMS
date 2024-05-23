/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */


import { createHmac, timingSafeEqual } from 'node:crypto'; // used to hash the received payload
import { Buffer } from 'node:buffer';

//using the node js crypto library to hash the received payload
function checkSignature(text,headers,githubsecrettoken){
	// for computing the hash
	const hmac=createHmac('sha256',githubsecrettoken); //hash obj
	hmac.update(text);
	const expectedSignature = hmac.digest('hex');
	const actualSignature = headers.get('x-hub-signature-256');
//signature comparison
	const trusted=Buffer.from(`sha256=${expectedSignature}`, 'ascii');
	const untrusted =  Buffer.from(actualSignature, 'ascii');

	// checking for the byte length
return trusted.byteLength==untrusted.byteLength 

}

async fetch(request, env, ctx) {
	if(request.method !== 'POST') {
	  return new Response('Try sending the POST request');
	}
	try {
	  const rawBody = await request.text();

	  if (!checkSignature(rawBody, request.headers, env.GITHUB_SECRET_TOKEN)) {
		return new Response("Wrong password, try again", {status: 403});
	  }
	} catch (e) {
	  return new Response(`Error:  ${e}`);
	}
  },