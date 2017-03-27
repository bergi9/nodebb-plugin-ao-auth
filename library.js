'use strict';

const winston = module.parent.require('winston');
const async = module.parent.require('async');
const passport = module.parent.require('passport');
const PassportLocal = module.parent.require('passport-local');
const db = module.parent.require('./database');
const user = module.parent.require('./user');
const meta = module.parent.require('./meta');

const Tedious = require('tedious');
const Request = Tedious.Request;
const TYPES = Tedious.TYPES;
const ConnectionPool = require('tedious-connection-pool');

const nconf = module.parent.require('nconf');
const dbConf = nconf.get('ao-auth');

const pool = new ConnectionPool(dbConf.pool, dbConf);

pool.on('error', function(err){
	winston.error('Pool Error: "%j"', err);
});

/**
 * @private
 * @param {string} sql - the sql query
 * @param {Object[]} types -  [{name, type, value}]
 * @param {string} types[].name -
 * @param {string} types[].type - tedious datatypes
 * @param {string|number} types[].value -
 * @param {function} cb - callback for results
 * @param {string} exec - name of function to be called
 */
function commonSql(sql, types, cb, exec){

	let startTime = Date.now();

	pool.acquire(function(err, connection){
		if(err) return cb(err);

		let result = [];

		let request = new Request(sql, function(err, rowCount){

			connection.release();

			if(err){
				winston.error('Request Error: "%j" - query: "%s"', err, sql);
				return cb(err);
			}

			winston.debug('execute time: %dms - called query: "%s"', Date.now() - startTime, sql);

			cb(null, result);
		});

		request.on('row', function(columns){

			let row = {};

			for(let i = 0, len = columns.length; i < len; i++){
				row[columns[i].metadata.colName] = columns[i].value;
			}

			result.push(row);
		});

		if(Array.isArray(types)){
			types.forEach(param => request.addParameter(param.name, TYPES[param.type], param.value));
		}

		if(connection[exec]){
			connection[exec](request);
		}else{
			cb(new Error('[Sql] unknown function'));
		}
	});
}

/**
 * execute sql (no stored procedure)
 * @param {string} sql - the sql query
 * @param {Object[]} [types] -  [{name, type, value}]
 * @param {string} [types[].name] -
 * @param {string} [types[].type] - tedious datatypes
 * @param {string|number} [types[].value] -
 * @param {function} cb - callback for results
 */
function execSql(sql, types, cb){
	if(arguments.length === 2){
		cb = types;
		types = undefined;
	}

	commonSql(sql, types, cb, 'execSql');
}

module.exports = {
	auth: function(){
		passport.use(new PassportLocal({passReqToCallback: true}, function(req, username, password, next){
			execSql('SELECT * FROM atum2_db_account.dbo.td_Account WHERE AccountName = @accName AND Password = @password', [
				{ name: 'accName', type: 'VarChar', value: username },
				{ name: 'password', type: 'VarChar', value: password }
			], function(err, res){
				if(err){
					next(err || new Error());
					return;
				}
				if(res.length === 0){
					return next(new Error('[[error:no-user]]'));
				}

				let uid, userData = {};
				async.waterfall([
					function (next) {
						user.getUidByUsername(res[0].AccountName, next);
					},
					function (_uid, next){
						if(!_uid){
							user.create({
								username: res[0].AccountName,
								email: res[0].email
							}, next);
							return;
						}
						next(null, _uid);
					},
					function (_uid, next) {
						if (!_uid) {
							return next(new Error('[[error:no-user]]'));
						}
						uid = _uid;
						user.auth.logAttempt(uid, req.ip, next);
					},
					function (next) {
						async.parallel({
							userData: function(next) {
								db.getObjectFields('user:' + uid, ['banned'], next);
							},
							isAdmin: function(next) {
								user.isAdministrator(uid, next);
							}
						}, next);
					},
					function (result, next) {
						userData = result.userData;
						userData.uid = uid;
						userData.isAdmin = result.isAdmin;

						if (!result.isAdmin && parseInt(meta.config.allowLocalLogin, 10) === 0) {
							return next(new Error('[[error:local-login-disabled]]'));
						}
						if (userData.banned && parseInt(userData.banned, 10) === 1) {
							return next(new Error('[[error:user-banned]]'));
						}
						user.auth.clearLoginAttempts(uid);
						next(null, userData, '[[success:authentication-successful]]');
					}
				], next);
			});
		}));
	}
};