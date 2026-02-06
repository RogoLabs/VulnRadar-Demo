#!/usr/bin/env python3
"""Validate watchlist YAML files."""
import os
import sys

import yaml


def validate_watchlist(path):
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    
    errors = []
    
    # Check expected keys exist and are lists
    expected_keys = ['vendors', 'products']
    for key in expected_keys:
        if key in data:
            if not isinstance(data[key], list):
                errors.append(f'{key} must be a list, got {type(data[key]).__name__}')
            else:
                # Check for empty strings
                empty = [i for i, v in enumerate(data[key]) if not v or (isinstance(v, str) and not v.strip())]
                if empty:
                    errors.append(f'{key} has empty values at indices: {empty}')
    
    # Validate optional arrays
    optional_arrays = ['exclude_vendors', 'exclude_products', 'cve_ids']
    for key in optional_arrays:
        if key in data and not isinstance(data[key], list):
            errors.append(f'{key} must be a list, got {type(data[key]).__name__}')
    
    return errors

if __name__ == '__main__':
    # Validate main watchlist
    errors = validate_watchlist('watchlist.yaml')
    if errors:
        print('❌ watchlist.yaml validation failed:')
        for e in errors:
            print(f'   - {e}')
        sys.exit(1)

    # Also validate example if it exists
    if os.path.exists('watchlist.example.yaml'):
        errors = validate_watchlist('watchlist.example.yaml')
        if errors:
            print('❌ watchlist.example.yaml validation failed:')
            for e in errors:
                print(f'   - {e}')
            sys.exit(1)

    print('✅ Watchlist files validated successfully')
