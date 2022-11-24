
init_val = 5

def register(gid, attrs):
    print(f"\tRegistering the guest {gid} with atributes {attrs.split()}")
    

def encrypt(filename , policy):
    data = None
    with open(filename, "rb") as f:
        # Write bytes to file
        print(f"Reading the file to encrypt with policy {policy}")
        data = f.read()

    with open("encr_file", "wb") as f:
        # Write bytes to file
        print("write encrypted info")
        f.write(data)

def decrypt(filename):
    data = None
    with open(filename, "rb") as f:
        # Write bytes to file
        print("Reading the file to decrypt")
        data = f.read()

    with open("decr_file", "wb") as f:
        # Write bytes to file
        print("write decrypted info")
        f.write(data)


def main(args):
    print(f"Received the arguments: {args.split()}")
    return "Good..." + str(init_val)


if __name__ == "__main__":
    main()