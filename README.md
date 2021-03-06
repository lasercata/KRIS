# KRIS
A PyQt5 python3 software that allow you to encrypt messages and files with secure ciphers. It it implements RSA, AES and KRIS. KRIS encrypt the message with AES (which is faster than RSA), and then encrypt the used AES key with RSA (like PGP do).

The name come from the esperanto "kriptosistemo" ("KRIptoSistemo").

You can generate your own RSA keys. They will be stored in `KRIS/Data/RSA_keys`, encrypted with AES, using the application password as base for the key.

![KRIS_v1 0 1_pic](https://user-images.githubusercontent.com/67599917/110215657-dea3a380-7ea2-11eb-8098-4158a87c3aa6.png)



## Requirements

To run the software, you need to have :

* [Python3](https://www.python.org/downloads/)
* [PyQt5](https://pypi.org/project/PyQt5/)


## Installing

Download or clone the repository :

```bash
git clone https://github.com/lasercata/KRIS.git
```

Make the launchers executable :

```bash
chmod +x *.py
```


## Running

### Run
In the main directory, run `./KRIS_gui.py`.

### Password
The default password is **`swiss_knife`**. It is used to encrypt the RSA keys, so you can leave KRIS on your USB key or on an other computer without the risk of having your keys stolen.

You can change the password in the Settings part.


## Authors

* **Lasercata** - [Lasercata](https://github.com/lasercata)
* **Elerias** - [Elerias](https://github.com/EleriasQueflunn)


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details
