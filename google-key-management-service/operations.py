""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request, exceptions as req_exceptions
from .google_api_auth import *
import base64

SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
KEY_MANAGEMENT_API = 'v1'

logger = get_logger('google-key-management-service')

CRYPTO_KEY_PURPOSE = {
    'Symmetric Encrypt/Decrypt': 'ENCRYPT_DECRYPT',
    'Asymmetric Sign': 'ASYMMETRIC_SIGN',
    'Asymmetric Decrypt': 'ASYMMETRIC_DECRYPT',
    'MAC Signing/Verification': 'CRYPTO_KEY_PURPOSE_UNSPECIFIED'
}


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        go = GoogleAuth(config)
        endpoint = go.host + "/" + endpoint
        token = go.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        logger.debug("Endpoint: {0}".format(endpoint))
        try:
            response = request(method, endpoint, headers=headers, params=params, json=data, verify=go.verify_ssl)
            logger.debug("Response Status Code: {0}".format(response.status_code))
            logger.debug("Response: {0}".format(response.text))
            logger.debug("API Header: {0}".format(response.headers))
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def check_payload(payload):
    final_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                final_payload[key] = nested
        elif value:
            final_payload[key] = value
    return final_payload


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def get_locations_list(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations'.format(KEY_MANAGEMENT_API, params.get('project_id'))
        query_parameter = {
            'filter': params.get('filter'),
            'pageSize': params.get('pageSize'),
            'pageToken': params.get('pageToken')
        }
        query_parameter = build_payload(query_parameter)
        logger.debug("Payload: {0}".format(query_parameter))
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_keyring(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings'.format(KEY_MANAGEMENT_API, params.get('project_id'),
                                                               params.get('location_id'))
        query_parameter = {
            'keyRingId': params.get('key_ring_id')
        }
        response = api_request('POST', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_keyring_list(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings'.format(KEY_MANAGEMENT_API, params.get('project_id'),
                                                               params.get('location_id'))
        query_parameter = {
            'pageSize': params.get('pageSize'),
            'pageToken': params.get('pageToken'),
            'filter': params.get('filter'),
            'orderBy': params.get('orderBy')
        }
        query_parameter = build_payload(query_parameter)
        logger.debug("Payload: {0}".format(query_parameter))
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_keyring_details(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}'.format(KEY_MANAGEMENT_API, params.get('project_id'),
                                                                   params.get('location_id'), params.get('key_ring_id'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_cryptokey(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys'.format(KEY_MANAGEMENT_API,
                                                                              params.get('project_id'),
                                                                              params.get('location_id'),
                                                                              params.get('key_ring_id'))
        purpose = params.get('purpose')
        if purpose:
            purpose = CRYPTO_KEY_PURPOSE.get(params.get('purpose'))
        query_parameter = {
            'cryptoKeyId': params.get('cryptoKeyId'),
            'skipInitialVersionCreation': params.get('skipInitialVersionCreation')
        }
        payload = {
            'purpose': purpose,
            'versionTemplate': {
                'protectionLevel': params.get('protectionLevel'),
                'algorithm': params.get('algorithm')
            },
            'nextRotationTime': params.get('nextRotationTime'),
            'rotationPeriod': params.get('rotationPeriod'),
            'labels': params.get('labels')
        }
        payload = check_payload(payload)
        query_parameter = build_payload(query_parameter)
        logger.debug("Payload: {0}".format(payload))
        logger.debug("Query Parameters: {0}".format(query_parameter))
        response = api_request('POST', url, connector_info, config, params=query_parameter, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cryptokey_list(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys'.format(KEY_MANAGEMENT_API,
                                                                              params.get('project_id'),
                                                                              params.get('location_id'),
                                                                              params.get('key_ring_id'))
        query_parameter = {
            'pageSize': params.get('pageSize'),
            'pageToken': params.get('pageToken'),
            'versionView': params.get('versionView'),
            'filter': params.get('filter'),
            'orderBy': params.get('orderBy')
        }
        query_parameter = build_payload(query_parameter)
        logger.debug("Payload: {0}".format(query_parameter))
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cryptokey_details(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}'.format(KEY_MANAGEMENT_API,
                                                                                  params.get('project_id'),
                                                                                  params.get('location_id'),
                                                                                  params.get('key_ring_id'),
                                                                                  params.get('cryptoKeyId'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def decrypt_cryptokey_details(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}:decrypt'.format(KEY_MANAGEMENT_API,
                                                                                          params.get('project_id'),
                                                                                          params.get('location_id'),
                                                                                          params.get('key_ring_id'),
                                                                                          params.get('cryptoKeyId'))
        auth_data = params.get('additionalAuthenticatedData')
        if auth_data:
            auth_data = base64.b64decode(auth_data.encode('ascii')).decode('ascii')
        ciphertext = params.get('ciphertext')
        if ciphertext:
            ciphertext = base64.b64decode(ciphertext.encode('ascii')).decode('ascii')
        payload = {
            'ciphertext': ciphertext,
            'additionalAuthenticatedData': auth_data,
            'ciphertextCrc32c': params.get('ciphertextCrc32c'),
            'additionalAuthenticatedDataCrc32c': params.get('additionalAuthenticatedDataCrc32c')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('POST', url, connector_info, config, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def encrypt_cryptokey_details(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}:encrypt'.format(KEY_MANAGEMENT_API,
                                                                                          params.get('project_id'),
                                                                                          params.get('location_id'),
                                                                                          params.get('key_ring_id'),
                                                                                          params.get('cryptoKeyId'))
        auth_data = params.get('additionalAuthenticatedData')
        if auth_data:
            auth_data = base64.b64decode(auth_data.encode('ascii')).decode('ascii')
        payload = {
            'plaintext': base64.b64decode(params.get('plaintext').encode('ascii')).decode('ascii'),
            'additionalAuthenticatedData': auth_data,
            'plaintextCrc32c': params.get('plaintextCrc32c'),
            'additionalAuthenticatedDataCrc32c': params.get('additionalAuthenticatedDataCrc32c')
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('POST', url, connector_info, config, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_cryptokey_version(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}/cryptoKeyVersions'.format(KEY_MANAGEMENT_API,
                                                                                                    params.get(
                                                                                                        'project_id'),
                                                                                                    params.get(
                                                                                                        'location_id'),
                                                                                                    params.get(
                                                                                                        'key_ring_id'),
                                                                                                    params.get(
                                                                                                        'cryptoKeyId'))
        payload = {
            'state': params.get('state'),
            'externalProtectionLevelOptions':
                {
                    'externalKeyUri': params.get('externalKeyUri')
                }
        }
        payload = check_payload(payload)
        logger.debug("Payload: {0}".format(payload))
        response = api_request('POST', url, connector_info, config, data=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cryptokey_version_list(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}/cryptoKeyVersions'.format(KEY_MANAGEMENT_API,
                                                                                                    params.get(
                                                                                                        'project_id'),
                                                                                                    params.get(
                                                                                                        'location_id'),
                                                                                                    params.get(
                                                                                                        'key_ring_id'),
                                                                                                    params.get(
                                                                                                        'cryptoKeyId'))
        query_parameter = {
            'pageSize': params.get('pageSize'),
            'pageToken': params.get('pageToken'),
            'view': params.get('versionView'),
            'filter': params.get('filter'),
            'orderBy': params.get('orderBy')

        }
        query_parameter = build_payload(query_parameter)
        logger.debug("Payload: {0}".format(query_parameter))
        response = api_request('GET', url, connector_info, config, params=query_parameter)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cryptokey_version_details(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}/cryptoKeyVersions/{5}'.format(
            KEY_MANAGEMENT_API, params.get('project_id'), params.get('location_id'), params.get('key_ring_id'),
            params.get('cryptoKeyId'), params.get('cryptoKeyVersionId'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def destroy_cryptokey_version(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}/cryptoKeyVersions/{5}:destroy'.format(
            KEY_MANAGEMENT_API, params.get('project_id'), params.get('location_id'), params.get('key_ring_id'),
            params.get('cryptoKeyId'), params.get('cryptoKeyVersionId'))
        response = api_request('POST', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def restore_cryptokey_version(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}/cryptoKeyVersions/{5}:restore'.format(
            KEY_MANAGEMENT_API, params.get('project_id'), params.get('location_id'), params.get('key_ring_id'),
            params.get('cryptoKeyId'), params.get('cryptoKeyVersionId'))
        response = api_request('POST', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_public_key_for_cryptokey_version(config, params, connector_info):
    try:
        url = '{0}/projects/{1}/locations/{2}/keyRings/{3}/cryptoKeys/{4}/cryptoKeyVersions/{5}/publicKey'.format(
            KEY_MANAGEMENT_API, params.get('project_id'), params.get('location_id'), params.get('key_ring_id'),
            params.get('cryptoKeyId'), params.get('cryptoKeyVersionId'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_locations_list': get_locations_list,
    'create_keyring': create_keyring,
    'get_keyring_list': get_keyring_list,
    'get_keyring_details': get_keyring_details,
    'create_cryptokey': create_cryptokey,
    'get_cryptokey_list': get_cryptokey_list,
    'get_cryptokey_details': get_cryptokey_details,
    'decrypt_cryptokey_details': decrypt_cryptokey_details,
    'encrypt_cryptokey_details': encrypt_cryptokey_details,
    'create_cryptokey_version': create_cryptokey_version,
    'get_cryptokey_version_list': get_cryptokey_version_list,
    'get_cryptokey_version_details': get_cryptokey_version_details,
    'destroy_cryptokey_version': destroy_cryptokey_version,
    'restore_cryptokey_version': restore_cryptokey_version,
    'get_public_key_for_cryptokey_version': get_public_key_for_cryptokey_version
}
