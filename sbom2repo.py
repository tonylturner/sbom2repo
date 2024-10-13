import json
import argparse
import logging
from purl2repo import get_source_repo_and_release


# Function to configure logging level
def configure_logging(verbose):
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )


# Set up logging for the script
logger = logging.getLogger(__name__)


# Function to load and parse CycloneDX SBOM
def load_cyclonedx_sbom(file_path):
    logger.debug(f"Opening SBOM file: {file_path}")
    with open(file_path, "r") as file:
        sbom_data = json.load(file)
    logger.debug(f"Successfully loaded SBOM data from: {file_path}")
    return sbom_data


# Function to process each purl and print the corresponding VCS repo and release info
def process_purls(sbom_data):
    # Check if "components" is in the SBOM
    if "components" not in sbom_data:
        logger.debug("No components found in the SBOM.")
        print("No components found in the SBOM.")
        return

    components = sbom_data["components"]
    logger.debug(f"Found {len(components)} components to process.")
    for component in components:
        if "purl" in component:
            purl_str = component["purl"]
            logger.debug(f"Processing purl: {purl_str}")
            try:
                # Use purl2repo library to get repository and release information
                result = get_source_repo_and_release(purl_str)
                logger.debug(f"Result for {purl_str}: {result}")
                print(f"Package: {result['package_name']}")
                if result["vcs_repo"]:
                    print(f"Repository: {result['vcs_repo']}")
                else:
                    print("No VCS repository found.")
                print(f"Version: {result['specified_version']}")

                # Print release URL if available
                if result.get("release_url"):
                    print(f"Release URL: {result['release_url']}")
                else:
                    print("No release URL found.")
                print()  # Blank line between components
            except ValueError as e:
                logger.error(f"Error processing purl: {purl_str} - {e}")
                print(f"Error processing purl: {purl_str} - {e}")
        else:
            logger.debug("No purl found for component.")
            print("No purl found for component.")


# Main function to load SBOM and process purls
def main():
    # Set up argparse to accept command-line arguments
    parser = argparse.ArgumentParser(
        description="Process CycloneDX SBOM and retrieve VCS repositories and releases."
    )
    parser.add_argument(
        "sbom_file_path", type=str, help="Path to the CycloneDX SBOM JSON file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose debug output"
    )

    # Parse arguments
    args = parser.parse_args()

    # Configure logging based on the -v argument
    configure_logging(args.verbose)

    # Log the SBOM file path being processed
    logger.debug(f"Loading SBOM from file: {args.sbom_file_path}")

    # Load the SBOM
    sbom_data = load_cyclonedx_sbom(args.sbom_file_path)

    # Process and print purl information
    process_purls(sbom_data)


if __name__ == "__main__":
    main()
