from PIL import Image
import os.path
from os import path
import math
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from colorama import init
from termcolor import cprint 
from pyfiglet import figlet_format
from rich import print
from rich.console import Console
from rich.table import Table
import os
import getpass
from rich.progress import track
import sys

DEBUG = False
console = Console()
headerText = "M6nMjy5THr2J"


def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode() if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def convertToRGB(img):
	try:
		rgba_image = img
		rgba_image.load()
		background = Image.new("RGB", rgba_image.size, (255, 255, 255))
		background.paste(rgba_image, mask = rgba_image.split()[3])
		print("[yellow]Converted image to RGB [/yellow]")
		return background
	except Exception as e:
		print("[red]Couldn't convert image to RGB [/red]- %s"%e)

def getPixelCount(img):
	width, height = Image.open(img).size
	return width*height



def encodeImage(image, message, filename):
    # Encoding the image with the given message
    with console.status("[green]Encoding image...") as status:
        try:
            width, height = image.size
            pix = image.getdata()

            current_pixel = 0
            tmp = 0
            x = 0
            y = 0

            # Iterate through the message and encode it in the image
            for ch in message:
                binary_value = format(ord(ch), '08b')
                p1 = pix[current_pixel]
                p2 = pix[current_pixel + 1]
                p3 = pix[current_pixel + 2]

                # Combine pixels into a list
                three_pixels = [val for val in p1 + p2 + p3]

                # Encode each character into the three pixels
                for i in range(8):
                    current_bit = binary_value[i]

                    if current_bit == '0':
                        if three_pixels[i] % 2 != 0:
                            three_pixels[i] = three_pixels[i] - 1 if three_pixels[i] == 255 else three_pixels[i] + 1
                    else:
                        if three_pixels[i] % 2 == 0:
                            three_pixels[i] = three_pixels[i] - 1 if three_pixels[i] == 255 else three_pixels[i] + 1

                current_pixel += 3
                tmp += 1

                # Encode termination condition
                if tmp == len(message):
                    # Make last bit odd to indicate end of message
                    if three_pixels[-1] % 2 == 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1
                else:
                    # Make last bit even to continue reading
                    if three_pixels[-1] % 2 != 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1
                
                # Convert list back to tuple
                three_pixels = tuple(three_pixels)
                
                # Place pixels back into the image
                st = 0
                end = 3
                for i in range(3):
                    image.putpixel((x, y), three_pixels[st:end])
                    st += 3
                    end += 3

                    if x == width - 1:
                        x = 0
                        y += 1
                    else:
                        x += 1

            # Determine the output file format based on the input image format
            output_format = image.format if image.format else "PNG"
            
            # Construct the output filename
            encoded_filename = filename.split('.')[0] + "-enc." + output_format.lower()
            
            # Save the encoded image in the same format and compression settings as the input image
            image.save(encoded_filename, format=output_format, quality=image.info.get("quality", 95), **image.info)

            print("\n")
            print("[yellow]Original File: [u]%s[/u][/yellow]" % filename)
            print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]" % encoded_filename)

        except Exception as e:
            print("[red]An error occurred - [/red]%s" % e)
            sys.exit(0)

def decodeImage(image):
    """
    Decode a hidden message from an image using steganography.

    Args:
        image (PIL.Image.Image): The image to decode the message from.

    Returns:
        str: The decoded message.
    """
    # Load pixel data from the image
    pix = image.getdata()
    current_pixel = 0
    decoded = ""
    
    while True:
        # Get three pixels at a time
        p1 = pix[current_pixel]
        p2 = pix[current_pixel + 1]
        p3 = pix[current_pixel + 2]
        
        # Combine pixel values into a list
        three_pixels = list(p1) + list(p2) + list(p3)
        
        # Create a binary string to store the binary representation of the character
        binary_value = ""
        
        # Iterate through the first 8 values (0-7) of three_pixels
        for i in range(8):
            if three_pixels[i] % 2 == 0:
                binary_value += "0"  # Add 0 for even pixel value
            else:
                binary_value += "1"  # Add 1 for odd pixel value
        
        # Convert the binary string to an ASCII character
        ascii_value = int(binary_value, 2)
        decoded += chr(ascii_value)
        
        # Move to the next set of pixels
        current_pixel += 3
        
        # Check the last pixel of the last set
        if three_pixels[-1] % 2 != 0:
            # If the last pixel's value is odd, we have reached the end of the message
            break
    
    return decoded


def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # Use SHA-256 over our key to get a proper-sized AES key
    
    # Extract the IV from the beginning
    IV = source[:AES.block_size]  
    
    # Decrypt the data
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    
    # Get padding value from the last byte
    padding = data[-1]
    
    # Check if the padding is valid
    if padding < 1 or padding > AES.block_size:
        raise ValueError("Invalid padding")
    
    # Check that all the padding bytes are the same and match the padding value
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding")
    
    # Remove the padding and return the decrypted data
    return data[:-padding].decode()





def test(img):
	image = Image.open(img)
	pix = image.load()
	print(pix[0])
	print(type(pix))

def print_credits():
	table = Table(show_header=True)
	table.add_column("Author",style="yellow")
	table.add_column("Contact",style="yellow")
	table.add_row("Nipun Anand", "anandonipun159@gmail.com ")
	console.print(table)



def insertHeaders(img):
	
	pass

def main():
	# insertHeaders(img)

	print("[cyan]Choose one: [/cyan]")
	op = int(input("1. Encode\n2. Decode\n>>"))

	if op==1:
		print("[cyan]Image path (with extension): [/cyan]")
		img = input(">>")
		if(not(path.exists(img))):
			raise Exception("Image not found!")

		
		print("[cyan]Message to be hidden: [/cyan]")
		message = input(">>")
		message = headerText + message
		if((len(message)+len(headerText))*3 > getPixelCount(img)):
			raise Exception("Given message is too long to be encoded in the image.")


		password=""
		while 1:
			print("[cyan]Password to encrypt (leave empty if you want no password): [/cyan]")
			password = getpass.getpass(">>")
			if password=="":
				break
			print("[cyan]Re-enter Password: [/cyan]")
			confirm_password = getpass.getpass(">>")
			if(password!=confirm_password):
				print("[red]Passwords don't match try again [/red]")
			else:
				break

		cipher=""
		if password!="":
			cipher = encrypt(key=password.encode(),source=message.encode())
			# Add header to cipher
			cipher = headerText + cipher
		else:
			cipher = message


		if DEBUG:
			print("[yellow]Encrypted : [/yellow]",cipher)

		image = Image.open(img)
		print("[yellow]Image Mode: [/yellow]%s"%image.mode)
		if image.mode!='RGB':
			image = convertToRGB(image)
		newimg = image.copy()
		encodeImage(image=newimg,message=cipher,filename=image.filename)

	elif op==2:
		print("[cyan]Image path (with extension): [/cyan]")
		img = input(">>")
		if(not(path.exists(img))):
			raise Exception("Image not found!")

		print("[cyan]Enter password (leave empty if no password): [/cyan]")
		password = getpass.getpass(">>")

		image = Image.open(img)

		cipher = decodeImage(image)


		header = cipher[:len(headerText)]

		if header.strip()!=headerText:
			print("[red]Invalid data![/red]")
			sys.exit(0)


		print()

		if DEBUG:
			print("[yellow]Decoded text: %s[/yellow]"%cipher)

		decrypted=""

		if password!="":
			cipher = cipher[len(headerText):]
			print("cipher : ",cipher)
			try:
				decrypted = decrypt(key=password.encode(),source=cipher)
			except Exception as e:
				print("[red]Wrong password![/red]")
				sys.exit(0)

		else:
			decrypted=cipher


		header = decrypted[:len(headerText)]

		if header!=headerText:
			print("[red]Wrong password![/red]")
			sys.exit(0)

		decrypted = decrypted[len(headerText):]



		print("[green]Decoded Text: \n[bold]%s[/bold][/green]"%decrypted)






if __name__ == "__main__":
	os.system('cls' if os.name == 'nt' else 'clear')
	cprint(figlet_format('IMGHIDE!', font='starwars'),'yellow', attrs=['bold'])
	print_credits()
	print()
	print("[bold]IMGHIDE[/bold] allows you to hide texts inside an image. You can also protect these texts with a password using AES-256.")
	print()
	
	main()