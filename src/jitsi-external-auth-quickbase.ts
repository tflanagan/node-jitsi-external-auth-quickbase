#!/usr/bin/env node

/*!
 * Copyright 2020 Tristian Flanagan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

'use strict';

/* Dependencies */
import { join } from 'path';
import FSConfig from 'fs-config';
import { debug } from 'debug';
import { QBTable } from 'qb-table';
import { QuickBase } from 'quickbase';
import { hash, compare } from 'bcrypt';
import { createInterface } from 'readline';

/* Debug */
const debugLog = debug('jitsi-external-auth');

/* Config */
const fsConfig = new FSConfig();
const config = fsConfig.loadDirSync<{
	quickbase: {
		connection: {
			realm: string;
			userToken: string;
		},
		users: {
			dbid: string;
			fids: {
				recordid: number;
				primaryKey: number;
				username: number;
				password: number;
				active: number;
			}
		}
	},
	encryption: {
		saltRounds: number;
	}
}>(join(__dirname, '..', 'config'));

/* Main */
const qb = new QuickBase(config.quickbase.connection);

const usersTable = new QBTable({
	quickbase: qb,
	dbid: config.quickbase.users.dbid,
	fids: config.quickbase.users.fids
});

const readline = createInterface({
	input: process.stdin,
	output: process.stdout,
	terminal: false
});

const parseLine = async (line: string): Promise<boolean> => {
	const parts = line.split(':');

	const action = parts[0];
	const username = parts[2];
	const password = parts.slice(3).join(':');

	switch(action){
		case 'auth':     return auth(username, password);
		case 'isuser':   return isUser(username);
		case 'setpass':  return setPass(username, password);
		case 'register': return register(username, password);
		default:        throw new Error(`Unknown prosody protocol send: ${line}`);
	}
};

const auth = async (username: string, password: string) => {
	const user = await getUser(username);

	if(!user.get('active')){
		throw new Error(`User ${username} is not active`);
	}

	const same = await compare(password, user.get('password'));

	if(!same){
		throw new Error('Invalid password');
	}

	return true;
};

const isUser = async (username: string) => {
	return !!(await getUser(username));
};

const setPass = async (username: string, password: string) => {
	const user = await getUser(username);
	const newPassword = await hash(password, config.encryption.saltRounds);

	user.set('password', newPassword);

	const results = await user.save([
		'password'
	]);

	return results.password === newPassword;
};

const getUser = async (username: string) => {
	const results = await usersTable.runQuery({
		where: `{'${usersTable.getFid('username')}'.EX.'${username}'}`
	});

	const record = results.records[0];

	if(!record){
		throw new Error(`User ${username} does not exist`);
	}

	return record;
};

const register = async (username: string, password: string) => {
	const exists = await isUser(username);

	if(exists){
		throw new Error(`User ${username} already exists`);
	}

	await usersTable.upsertRecord({
		username: username,
		password: await hash(password, config.encryption.saltRounds),
		active: true
	}, true);

	return true;
};

/* Bang */
readline.on('line', async (line) => {
	try {
		const results = await parseLine(line);

		console.log(results ? 1 : 0);
	}catch(err){
		debugLog(`Error processing line: ${err.message}`);

		console.log(0);
	}
});