def parse_byte(byte_str):
    return int(byte_str, 16).to_bytes(1, byteorder='big')

def parse_file(input_file, output_file):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    with open(output_file, 'wb') as f:
        for line in lines:
            # Split line by whitespace
            line = line[line.find(':') + 1:]
            parts = line.strip().split()
            print(parts)
            # Parse each byte and write to output file
            for byte_str in parts:
                byte = parse_byte(byte_str)
                f.write(byte)

if __name__ == "__main__":
    input_file = "vdso_mem"  # Replace with your input file name
    output_file = "vdso_mem_parsed"  # Replace with your output file name

    parse_file(input_file, output_file)
    print("Parsing complete.")
