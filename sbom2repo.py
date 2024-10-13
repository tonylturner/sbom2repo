import json
import argparse
from purl2repo import get_source_repo_and_release

# Function to load and parse CycloneDX SBOM
def load_cyclonedx_sbom(file_path):
    with open(file_path, 'r') as file:
        sbom_data = json.load(file)
    return sbom_data

# Function to process each purl and print the corresponding VCS repo and release info
def process_purls(sbom_data):
    # Check if "components" is in the SBOM
    if 'components' not in sbom_data:
        print("No components found in the SBOM.")
        return

    components = sbom_data['components']
    for component in components:
        if 'purl' in component:
            purl_str = component['purl']
            try:
                # Use purl2repo library to get repository and release information
                result = get_source_repo_and_release(purl_str)
                print(f"Package: {result['package_name']}")
                if result['vcs_repo']:
                    print(f"Repository: {result['vcs_repo']}")
                else:
                    print("No VCS repository found.")
                print(f"Version: {result['specified_version']}")
                
                # Print release URL if available
                if result.get('release_url'):
                    print(f"Release URL: {result['release_url']}")
                else:
                    print("No release URL found.")
                
                print()  # Blank line between components
            except ValueError as e:
                print(f"Error processing purl: {purl_str} - {e}")
        else:
            print("No purl found for component.")

# Main function to load SBOM and process purls
def main():
    # Set up argparse to accept command-line arguments
    parser = argparse.ArgumentParser(description="Process CycloneDX SBOM and retrieve VCS repositories and releases.")
    parser.add_argument('sbom_file_path', type=str, help="Path to the CycloneDX SBOM JSON file")

    # Parse arguments
    args = parser.parse_args()

    # Load the SBOM
    sbom_data = load_cyclonedx_sbom(args.sbom_file_path)
    
    # Process and print purl information
    process_purls(sbom_data)

if __name__ == "__main__":
    main()
