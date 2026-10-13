import os
import pytest
from fastapi.testclient import TestClient

os.environ["DATA_DIR"] = "/tmp/vexon_test_data"
from main import app, _initial_admin_pw, SESSION_COOKIE

@pytest.fixture
def test_client():
    with TestClient(app) as client:
        yield client

@pytest.fixture
def auth_cookies(test_client):
    response = test_client.post("/api/login", json={"username": "admin", "password": _initial_admin_pw})
    assert response.status_code == 200
    token = response.cookies.get(SESSION_COOKIE)
    return {SESSION_COOKIE: token}

def test_login_and_me(test_client, auth_cookies):
    res = test_client.get("/api/me", cookies=auth_cookies)
    assert res.status_code == 200
    data = res.json()
    assert data.get("authenticated") is True
    assert data.get("username") == "admin"
    assert data.get("role") == "admin"

def test_link_crud(test_client, auth_cookies):
    create_res = test_client.post(
        "/api/links",
        json={
            "label": "Test Link 1",
            "limit_value": 5,
            "limit_unit": "GB",
            "expires_days": 7,
            "protocol": "vless-ws",
            "port": 2053,
            "ip_limit": 2,
            "speed_limit_value": 10,
            "speed_limit_unit": "MBIT",
        },
        cookies=auth_cookies,
    )
    assert create_res.status_code == 200
    link_data = create_res.json()
    uuid = link_data["uuid"]
    assert link_data["label"] == "Test Link 1"
    assert link_data["port"] == 2053
    assert link_data["ip_limit"] == 2

    list_res = test_client.get("/api/links", cookies=auth_cookies)
    assert list_res.status_code == 200
    links = list_res.json()["links"]
    assert any(l["uuid"] == uuid for l in links)

    hist_res = test_client.get(f"/api/links/{uuid}/history", cookies=auth_cookies)
    assert hist_res.status_code == 200
    hist_data = hist_res.json()
    assert len(hist_data["days"]) == 30

    patch_res = test_client.patch(
        f"/api/links/{uuid}",
        json={"label": "Updated Test Link", "active": False},
        cookies=auth_cookies,
    )
    assert patch_res.status_code == 200

    del_res = test_client.delete(f"/api/links/{uuid}", cookies=auth_cookies)
    assert del_res.status_code == 200

def test_sub_group_crud_and_public_page(test_client, auth_cookies):
    link_res = test_client.post("/api/links", json={"label": "Sub Link 1"}, cookies=auth_cookies)
    uuid = link_res.json()["uuid"]

    create_sub = test_client.post(
        "/api/subs",
        json={
            "name": "VIP Group",
            "desc": "VIP Users Sub Group",
            "uuids": [uuid],
            "password": "subpassword123",
        },
        cookies=auth_cookies,
    )
    assert create_sub.status_code == 200
    sub_id = create_sub.json()["id"]

    pub_res = test_client.get(f"/api/public/sub-group/{sub_id}")
    assert pub_res.status_code == 200
    pub_data = pub_res.json()
    assert pub_data["locked"] is True
    assert pub_data["links"] == []

    unlock_res = test_client.post(f"/api/public/sub-group/{sub_id}/unlock", json={"password": "subpassword123"})
    assert unlock_res.status_code == 200
    assert unlock_res.json()["ok"] is True

    page_res = test_client.get(f"/p/group/{sub_id}")
    assert page_res.status_code == 200
    assert "Vexon Sub Group" in page_res.text

    del_sub = test_client.delete(f"/api/subs/{sub_id}", cookies=auth_cookies)
    assert del_sub.status_code == 200

def test_system_backup_and_restore(test_client, auth_cookies):
    backup_res = test_client.get("/api/system/backup", cookies=auth_cookies)
    assert backup_res.status_code == 200
    backup_json = backup_res.json()
    assert "links" in backup_json
    assert "subs" in backup_json
    assert "users" in backup_json

    restore_res = test_client.post("/api/system/restore", json=backup_json, cookies=auth_cookies)
    assert restore_res.status_code == 200
    assert restore_res.json()["ok"] is True
