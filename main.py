import os
from base64 import b64decode, b64encode
from pathlib import Path

from fastapi import FastAPI, UploadFile, HTTPException, Body
from starlette.responses import RedirectResponse
from typing_extensions import Annotated

from core import (
    certificate_info,
    certificates_store,
    get_signer,
    get_signature,
    get_unsigned,
    gost_hash,
)

app = FastAPI()


@app.get('/')
def index():
    """
    Документация swagger на главной странице.
    :return: Редирект /docs#
    """

    return RedirectResponse('docs')


@app.get('/certificate')
def get_certificates():
    """
    Выдает информцию о всех сертификатах в хранилище.
    """

    store = certificates_store()
    certificates = {
        cert_num: certificate_info(store.Item(cert_num))
        for cert_num in range(1, store.Count + 1)
    }

    return {'certificates': certificates}


@app.post('/certificate/install')
def unpack_container(container: UploadFile):
    """
    Установка цепочки сертификатов и ключей из контейнера pfx(p12) в хранилище.
    """

    if not Path(container.filename).suffix in ('.pfx', '.p12'):
        raise HTTPException(400, detail='Expect format <.pfx> or <.p12>')

    tmp_certificate = Path('temp', container.filename)
    tmp_certificate.write_bytes(container.file.read())

    os.system(f'./certmgr -inst -pfx -file {tmp_certificate}')
    os.remove(tmp_certificate)
    return {
        'status': f'certificates from container '
                  f'"{container.filename}" installed'
    }


@app.post('/sign/{cert}')
async def sign_file(
        cert: int,
        file: UploadFile,
        pin: Annotated[str, Body()] = ''
):
    """
    Создание подписи файла.
    Если у ключа есть пароль, необходимо указать его.
    Возвращает json с подписанными данными
    и имя файла с прикрепленной подписью.
    """

    cert = certificates_store().Item(cert)
    signer = get_signer(cert, pin)
    try:

        signature = get_signature(await file.read(), signer)
    except Exception:
        raise HTTPException(
            400,
            detail='The private key cannot be accessed '
                   'because the wrong PIN was presented.'
        )

    # path_sig = Path(__file__).parent / 'temp/sig_test.p7s'
    # # path_sig.write_text(signature)
    # path_sig.write_bytes(b64decode(signature))

    return {
        'signedContent': signature,
        'filename': f'{file.filename}.p7s',
    }


@app.post('/unsign')
async def unsign_file(file: UploadFile):
    """
    Удаление подписи из файла. Возвращает json оригинала документа и имя файла.
    """

    signature = (await file.read())
    unsigned_data = get_unsigned(signature)

    # path_unsig = Path(__file__).parent / 'temp/unsig_test.pdf'
    # path_unsig.write_bytes(b64decode(unsigned_data))

    return {
        'Content': unsigned_data,
        'filename': f'{file.filename.replace(".p7s", "")}'
    }


@app.post('/hashsign/{cert}')
async def sign_hash(
        cert: int,
        file: UploadFile,
        pin: Annotated[str, Body()] = ''
):
    """
    Подписание хеша файла.
    """

    cert = certificates_store().Item(cert)
    signer = get_signer(cert, pin)
    try:
        hash_file = gost_hash(await file.read())
        signature = get_signature(hash_file, signer)
    except Exception:
        raise HTTPException(
            400,
            detail='The private key cannot be accessed '
                   'because the wrong PIN was presented.'
        )

    return {
        'signedContent': signature,
        'filename': f'{file.filename}.p7s',
    }