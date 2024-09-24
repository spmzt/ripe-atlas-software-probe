#
# JSON string generation in shell scripts
# Copyright (c) 2022 RIPE NCC
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
# 

# Global variables
_json_instance_num=0
_json_max_instances=2048

#
# Internal function to add JSON object
# Usage: _json_add_object <variable>
# Newly generated entry point to class will be exported to <variable>
# in the global environment.
#
_json_add_object( )
{
	local name="_json_instance_${_json_instance_num}"

	eval "${name}() { _json_call \"${_json_instance_num}\" \"\${@}\"; }"
	export _json_instance_num=$(( ( _json_instance_num + 1 ) % _json_max_instances ))
	new array "${name}_keys"
	eval "export ${1}=${name}"
}

#
# Internal function to invoke class methods
# Usage: _json_call <instance number> <method> <method args>
# NOTE: Only called from the function entry point,
#  not intended to be called directly.
# <instance number> generated by json_add_object()
# <method> name of the class method to invoke
# <method args> any arguments to be passed to class method
#
_json_call( )
{
	local handle="_json_instance_${1}"
	shift
	local method="${1}"
	shift

	eval "json_${method}" "${handle}" \"\${@}\"
}

#
# Method to add values to a JSON variable
# Usage: json_add <handle> <variable name> <variable type> [<value>]
# <handle> generated by _json_call()
# <variable name> name of JSON variable to add
# <variable type> type of JSON variable to add (e.g. string / float)
# <value> value for JSON variable, optional for null type. This must
#  a global variable name for object types
#
json_add( )
{
	_json_set "${1}" "${2}" "${3}" "${4}" 'append'
}

#
# Method to set the value on a JSON variable
# Usage: json_set <handle> <variable name> <variable type> [<value>]
# <handle> generated by _json_call()
# <variable name> name of JSON variable to add
# <variable type> type of JSON variable to add (e.g. string / float)
# <value> value for JSON variable, optional/empty for null type.
#  This must be a global variable name for object types
#
json_set( )
{
	_json_set "${1}" "${2}" "${3}" "${4}" 'set'
}

#
# Internal method to add/set the value on a JSON variable
# Usage: _json_set <handle> <variable name> <variable type> [<value>]
# <handle> generated by _json_call()
# <variable name> name of JSON variable to add
# <variable type> type of JSON variable to add (e.g. string / float)
# <value> value for JSON variable, optional/empty for null type.
#  This must be a global variable name for object types
# <action> Whether to append to or set the value of a JSON variable.
#
_json_set( )
{
	local handle="${1}"
	local name="${2}"
	local type="${3}"
	local value="${4}"
	local action="${5}"
	local tmp=''

	if [ "${type}" = 'object' ]; then
		_json_add_object "${value}"
		eval "tmp=\${${value}}"
		value="${tmp}"
	fi	
	_json_add_data "${handle}" "${name}" "${type}" "${value}" "${action}"
}

#
# Internal method to add/set the value on a JSON variable
# Usage: _json_add_data <handle> <variable name> <variable type> [<value>]
# <handle> generated by _json_call()
# <variable name> name of JSON variable to add
# <variable type> type of JSON variable to add (e.g. string / float)
# <value> value for JSON variable, optional/empty for null type.
#  This must be a global variable name for object types
# <action> Whether to append to or set the value of a JSON variable.
#
_json_add_data( )
{
	local handle="${1}"
	local name="${2}"
	local type="${3}"
	local value="${4}"
	local action="${5}"
	local prefix="${handle}_${name}"
	local types
	local keys
	local vals
	local tmp
	
	if [ -z "${action}" ]; then
		action='set'
	fi

	eval "keys=\${${handle}_keys}"

	tmp="${prefix}_type"
	eval "types=\${${tmp}}"
	if [ -z "${types}" ]; then
		new array "${tmp}"
		eval "types=\${${tmp}}"
	fi

	tmp="${prefix}_val"
	eval "vals=\${${tmp}}"
	if [ -z "${vals}" ]; then
		new array "${tmp}"
		eval "vals=\${${tmp}}"
	fi

	if [ $(${keys} find "${name}") -lt 0 ]; then
		${keys} append "${name}"
	fi

	if [ "${action}" = 'append' ]; then
		eval export "${prefix}_isarray=1"
		${types} append "${type}"
		${vals} append "${value}"
		
	else
		eval export "${prefix}_isarray=0"
		${types} set "${type}"
		${vals} set "${value}"
	fi
}

#
# Internal method to remove data of a non-object JSON type
# Usage: _json_destroy_data <handle> <variable name>
# <handle> generated by _json_call()
# <variable name> name of JSON variable to remove
#
_json_destroy_data( )
{
	local handle="${1}"
	local name="${2}"
	local prefix="${handle}_${name}"

	delete "${prefix}_type"
	delete "${prefix}_val"
	unset "${prefix}_isarray"
}

#
# Internal method to remove data of a JSON array
# Usage: _json_destroy_array <handle> <variable name>
# <handle> generated by _json_call()
# <variable name> name of JSON variable to remove
#
_json_destroy_array( )
{
	local handle="${1}"
	local name="${2}"
	local prefix="${handle}_${name}"
	local index=1
	local vals
	local types
	local size
	local val
	local entry
	local type

	eval "types=\${${prefix}_type}"
	eval "vals=\${${prefix}_val}"
	size=$(${types} get 0)

	while [ ${index} -le ${size} ]; do
		val=$(${vals} get ${index})
		type=$(${types} get ${index})
		if [ "${type}" = 'object' ]; then
			_json_destroy_object "${val}"
		fi

		index=$((index + 1))
	done
	_json_destroy_data "${handle}" "${name}"
}

#
# Internal method to remove data of a JSON object
# Usage: _json_destroy_object <handle>
# <handle> generated by _json_call()
#
_json_destroy_object( )
{
	local handle="${1}"
	local index=1
	local keys
	local size
	local entry
	local tmp

	eval "keys=\${${handle}_keys}"

	size=$(${keys} get 0)

	while [ ${index} -le ${size} ]; do
		entry=$(${keys} get ${index})

		_json_destroy_array "${handle}" "${entry}"

		index=$((index + 1))
	done
	delete "${handle}_keys"
	unset ${handle}
}

#
# Internal method to display data of a JSON type
# Usage: _json_encode_value <type> <value>
# <type> JSON type
# <value> stringified value to write to stdout
#
_json_encode_value( )
{
	local type="${1}"
	local val="${2}"

	case "${type}" in
		'object')
			_json_encode_object "${val}"
			;;

		'string')
			echo -n "\"${val}\""
			;;

		'boolean')
			case "${val}" in
				'1'|'yes'|'true')
					echo -n 'true'
					;;

				'0'|'no'|'false'|*)
					echo -n 'false'
					;;
			esac
			;;

		'integer'|'float')
			echo -n "${val}"
			;;

		'null'|*)
			echo -n 'null'
			;;
	esac
}

#
# Internal method to display data of a JSON array
# Usage: _json_encode_value <handle> <name>
# <handle> generated by _json_call()
# <name> name of JSON array to write to stdout
#
_json_encode_array( )
{
	local handle="${1}"
	local name="${2}"
	local prefix="${handle}_${name}"
	local index=1
	local types
	local vals
	local size
	local type
	local output
	local val
	local entry
	local isarray

	eval "types=\${${prefix}_type}"
	eval "vals=\${${prefix}_val}"
	size=$(${types} get 0)
	eval "isarray=\"\${${prefix}_isarray}\""

	echo -n "\"${name}\":"
	if [ ${isarray} -ne 0 ]; then
		echo -n '[ '
	fi

	while [ ${index} -le ${size} ]; do
		val=$(${vals} get ${index})
		type=$(${types} get ${index})
		if [ ${index} -gt 1 ]; then
			echo -n ','
		fi

		_json_encode_value "${type}" "${val}"

		index=$((index + 1))
	done

	if [ ${isarray} -ne 0 ]; then
		echo -n ' ]'
	fi
}

#
# Internal method to display data of a JSON object
# Usage: _json_encode_object <handle> <name>
# <handle> generated by _json_add()
#
_json_encode_object( )
{
	local handle="${1}"
	local keys
	local size
	local index=1
	local entry

	eval "keys=\${${handle}_keys}"
	size=$(${keys} get 0)

	echo -n '{ '
	while [ ${index} -le ${size} ]; do
		entry=$(${keys} get ${index})

		if [ $index -gt 1 ]; then
			echo -n ','
		fi

		_json_encode_array "${handle}" "${entry}"

		index=$((index + 1))
	done
	echo -n ' }'
}

#
# Method to display data of a JSON object
# Usage: json_encode <instance number>
# <instance number> generated by json_add_object()
#
json_encode( )
{
	_json_encode_object "${1}"
	echo ''
}

#
# Method to clean up data of a JSON object
# Usage: json_destructor <instance number>
# <instance number> generated by json_add_object()
#
json_destructor( )
{
	_json_destroy_object "${1}"
}

#
# Method to create a JSON object
# Usage: json_constructor <variable>
# Newly generated entry point to class will be exported to <variable>
# in the global environment.
#
json_constructor( )
{
	_json_add_object "${1}"
}