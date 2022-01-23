"""
# Web service for home_nmap
# Author: Jose Vicente Nunez Zuleta (kodegeek.com@protonmail.com)
"""
import typing
from functools import lru_cache
from typing import Optional

import uvicorn
from fastapi_simple_security import api_key_router, api_key_security

from home_nmap import __version__, config
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from http import HTTPStatus

from home_nmap.query import NDISHtml, target_validator
from home_nmap.system import HostIface, NMapRunner

app: typing.Union[FastAPI] = FastAPI()
app.include_router(api_key_router, prefix="/auth", tags=["_auth"])


@lru_cache()
def get_settings():
    return config.Settings()


@app.get("/version")
def version():
    """
    Get the home_nmap application version.
    This request doesn't require authorization.
    @return: JSON with version information
    """
    return {"version": __version__}


@app.get("/local_networks", dependencies=[Depends(api_key_security)])
def local_networks():
    """
    Get the available local networks where home_nmap runs
    @return: List with local networks in CIDR format
    """
    response = JSONResponse(jsonable_encoder(HostIface().get_local_networks()))
    return response


@app.get("/scan", dependencies=[Depends(api_key_security)])
def scan(
        target: Optional[str] = None,
        full_advisories=True
):
    """
    Scan a target to get service information.
    Note, FastAPI has a query validator, but I decided to use my own as I look for bad regexp:
    Query(None, min_length=MIN_LEN_TARGET, max_length=MAX_LEN_TARGET)
    @param target: Override local network with custom targets, in NMAP format.
    @param full_advisories: If false, skip the summary information from the advisories
    @return: JSON containing the results of the scan
    """
    try:
        scanner = NMapRunner()
        args, scan_results, stderr = scanner.scan(hosts=target_validator(target))
        enriched_results = {
            'args': args,
            'hosts': []
        }
        if not scan_results:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                                detail=f"Got no results from scanning target={target}")
        cpe_details = NDISHtml().correlate_nmap_with_nids(scan_results)
        for host_data in scan_results:
            enriched_host_data = {
                'address': host_data['address'],
                'ports': []
            }
            ports = host_data['ports']
            for port_data in ports:
                advisories = []
                # Unroll the advisories, if any ...
                for cpe in port_data['cpes']:
                    if cpe in cpe_details:  # Service may not have an advisory
                        for nids in cpe_details[cpe]:
                            if full_advisories:
                                advisories.append({
                                    'link': nids.link,
                                    'summary': nids.summary,
                                    'score': nids.score
                                })
                            else:
                                advisories.append({
                                    'link': nids.link,
                                    'summary': '',  # For consistency
                                    'score': nids.score
                                })
                enriched_host_data['ports'].append(
                    {
                        'cpes': port_data['cpes'],
                        'advisories': advisories,
                        'protocol': port_data['protocol'],
                        'port_id': port_data['port_id'],
                        'service': [
                            {port_data['service_name']},
                            {port_data['service_product']},
                            {port_data['service_version']}
                        ]
                    }
                )
            enriched_results['hosts'].append(enriched_host_data)
        return enriched_results
    except ValueError as exp:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(exp))
    except TypeError as exp:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(exp))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
