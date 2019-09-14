#!/usr/bin/env python
# -*- coding: utf-8 -*-
from subprocess import PIPE, Popen
from typing import Dict, List, NewType, Tuple, Union

Result = NewType("Result", dict)

PINNED_VERSION = [2, 0, 0]
PINNED_CURVE = "sr25519"


class SubstrateKeyManager:
    def __init__(self):
        self.check_args = ["subkey", "--version"]
        self.sk_generate_args = ["subkey", "generate"]
        self.sk_sign_args = []
        self.sk_verify_args = []
        self.verify_messagee = b"Signature verifies correctly.\n"
        assert self._check_subkey()

    @staticmethod
    def _shproc(cmd_args: List) -> Tuple:
        ''' generic subprocess handler '''
        out, err = b"", b""
        try:
            proc = Popen(cmd_args, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate()
        except FileNotFoundError as exc:
            err = "Target {} not found: {}. Make sure it is spelled correclty and installed."
            err.format(cmd_args[0], exc.args).encode("utf8")
        except Exception as exc:
            # TODO: raise straight up ?
            err = "Target {} not found: {}. Make sure it is spelled correclty and installed."
            err.format(cmd_args[0], exc.args).encode("utf8")

        return (out, err)

    def _verify_version(self, reference_version: List, version_bstring: bytes) -> bool:
        ''' subkey version checker '''
        _v = version_bstring.decode().strip("\n").split(" ")[1].split(".")
        _v[:] = [int(i) for i in _v]
        return _v == reference_version

    def _check_subkey(self, ) -> Union[bool, Exception]:
        out, err = self._shproc(self.check_args)
        if not out:
            raise Exception(err)

        if not self._verify_version(PINNED_VERSION, out):
            msg = "Invalid subkey version {} but expect {}".format(out, PINNED_VERSION)
            raise Exception(msg)

        return True

    def sk_generate(self, chain: str = "substrate") -> Tuple:
        ''' generate a random substrate account for the specified chain '''
        # assert self._check_subkey()
        cmd_args = self.sk_generate_args
        cmd_args.insert(1, chain)
        cmd_args.insert(1, "--network")

        out, err = self._shproc(cmd_args)
        if err:
            return {}, err

        res = {}
        for s in out.decode().strip(" ").split("\n"):
            if s:
                if s.startswith("Secret phrase"):
                    _ = s.split("Secret phrase ")
                    res["Secret phrase"] = _[1].strip("`").rstrip(" is account :``")
                else:
                    _ = s.split(":")
                    res[_[0].strip(" ")] = _[1].strip(" ")
        return (res, err)

    def sk_sign(self, payload: str, seed: str) -> Tuple:
        ''' seed can be private key or mnemonic '''

        if not payload:
            return b"", b"Need payloadto sign message"

        if not seed:
            return b"", b"Need seed or mnemonic to sign message"

        proc = Popen(["echo", payload], stdout=PIPE)
        proc.wait()
        proc = Popen(['subkey', "sign", seed], stdin=proc.stdout, stdout=PIPE, stderr=PIPE)
        proc.wait()
        out, err = proc.communicate()
        if not err:
            out = out.decode().strip("\n")
            out.encode()
        return out, err

    def sk_verify(self, payload: str, signature: str, seed: str) -> Tuple:
        ''' seed can be private key or mnemonic '''
        if seed is None:
            return False, b"Need seed or mnemonic to verify message"

        proc = Popen(["echo", payload], stdout=PIPE)
        proc.wait()
        proc = Popen(['subkey', "verify", signature, seed], stdin=proc.stdout, stdout=PIPE, stderr=PIPE)
        proc.wait()
        out, err = proc.communicate()
        if out != self.verify_messagee:
            out = False
        else:
            out = True
        return out, err


# tests
def test_sh_proc():
    out, err = SubstrateKeyManager._shproc(["ls"])
    assert not err

    out, err = SubstrateKeyManager._shproc(["abcdec"])
    assert not out
    assert err.startswith("Target")


def test_generate():
    pass


def test_sign():
    skm = SubstrateKeyManager()
    g_out, g_err = skm.sk_generate()
    assert not g_err

    payload = "hello, py test"
    seed = g_out['Secret seed']
    mnemonic = g_out['Secret phrase']

    out, err = skm.sk_sign("", seed)
    assert not out
    assert err.decode().startswith("Need payload")

    out, err = skm.sk_sign(payload, "")
    assert not out
    assert err.decode().startswith("Need seed")

    out, err = skm.sk_sign(payload, seed)
    assert not err
    assert len(out) == 128

    out, err = skm.sk_sign(payload, mnemonic)
    assert not err
    assert len(out) == 128


def test_verify():
    skm = SubstrateKeyManager()
    g_out, g_err = skm.sk_generate()
    assert not g_err

    payload = "hello, py test"
    seed = g_out['Secret seed']
    mnemonic = g_out['Secret phrase']

    out, err = skm.sk_sign(payload, seed)
    out, err = skm.sk_verify(payload, out, seed)
    assert not err
    assert out

    out, err = skm.sk_sign(payload, mnemonic)
    out, err = skm.sk_verify(payload, out, mnemonic)
    assert not err
    assert out
